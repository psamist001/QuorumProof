import { Router, Request, Response } from 'express';
import type { simulateCall as SimulateCallType } from '../soroban.js';
import { SearchIndex, type SearchOptions, type CredentialRecord as SearchCredentialRecord } from '../searchIndex.js';
import { MetadataHashCache } from '../services/metadataHashCache.js';
import { ShardedCredentialStore } from '../services/shardedStorage.js';
import { SearchIndexStore } from '../services/searchIndexStore.js';
import { SearchRebuildManager } from '../services/searchRebuildManager.js';
import { parseFilterTree } from '../services/searchFilterParser.js';
// #1563: Simple credential_type= / status= filter validation middleware
import { credentialQueryFilterMiddleware } from '../middleware/credentialQueryFilter.js';

export type SorobanClient = {
  simulateCall: typeof SimulateCallType;
  u64Val: (n: number | bigint) => ReturnType<typeof SimulateCallType>;
  u32Val: (n: number) => ReturnType<typeof SimulateCallType>;
  addressVal: (a: string) => ReturnType<typeof SimulateCallType>;
};

/** Recursively convert BigInt values to strings for JSON serialization. */
function serializeBigInt(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(serializeBigInt);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, serializeBigInt(v)])
    );
  }
  return value;
}

type CredentialRecord = SearchCredentialRecord;

const VALID_SORT_KEYS = ['id', 'type', 'relevance', 'created_at', 'updated_at', 'recency', 'reputation'];

export function createCredentialsRouter(soroban: SorobanClient) {
  const router = Router();
  const store = new SearchIndexStore();
  const metadataHashCache = new MetadataHashCache();
  const shardedStore = new ShardedCredentialStore();
  const rebuildManager = new SearchRebuildManager();
  let indexedCredentials: Set<string> = new Set();
  let indexVersion = 0;

  // The live, queryable index. Rebuilds build a fresh instance off to the
  // side and only swap this reference in once fully built, so `/search`
  // always sees either the old index or the new one, never a partial one.
  let currentIndex = new SearchIndex();

  // Hydrate from local disk (no chain RPC) so a process restart doesn't
  // require re-scanning the chain before search works again.
  {
    const persisted = store.all();
    if (persisted.length > 0) {
      currentIndex.indexCredentials(persisted);
      for (const cred of persisted) indexedCredentials.add(cred.id);
      indexVersion++;
    }
  }

  /**
   * Fetches every credential from the chain (1x get_credential_count + Nx
   * get_credential). Only credentials that are new or changed since the last
   * time they were persisted get written to `store` and re-indexed — repeat
   * polls patch the index incrementally instead of rebuilding it from
   * scratch, and diffing happens against the on-disk store so it's true
   * across process restarts too.
   */
  async function populateIndex(): Promise<void> {
    try {
      const credCount: bigint = await soroban.simulateCall('get_credential_count', []);
      const total = Number(credCount);

      for (let i = 1; i <= total; i++) {
        try {
          const cred = await soroban.simulateCall('get_credential', [soroban.u64Val(i)]);
          const credRecord = serializeBigInt(cred) as CredentialRecord;
          // Ensure id is a string
          credRecord.id = String(credRecord.id || i);

          const existing = store.get(credRecord.id);
          const changed =
            !existing ||
            existing.version !== credRecord.version ||
            existing.metadata_hash !== credRecord.metadata_hash ||
            existing.revoked !== credRecord.revoked ||
            existing.suspended !== credRecord.suspended;

          indexedCredentials.add(credRecord.id);
          metadataHashCache.set(credRecord.id, credRecord.metadata_hash, cred as Record<string, unknown>);
          shardedStore.set(credRecord);

          if (changed) {
            store.set(credRecord);
            currentIndex.indexCredential(credRecord);
          }
        } catch {
          // skip missing/expired credentials
        }
      }
      indexVersion++;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('Failed to populate search index:', msg);
    }
  }

  /**
   * GET /api/credentials/search
   * Advanced search with filters, full-text search, ranking, deduplication,
   * and cursor-based pagination.
   * Query params:
   *   - q: full-text search query
   *   - type: credential type (supports multiple: type=1&type=2)
   *   - issuer: issuer address (supports multiple)
   *   - issuer_type: issuer type (supports multiple)
   *   - subject: subject address
   *   - status: active|revoked|suspended
   *   - jurisdiction: ISO 3166-1/3166-2 or supranational group code
   *     (supports multiple: jurisdiction=US&jurisdiction=EU). Hierarchical —
   *     "US" matches "US-CA" etc., "EU" matches any EU member country.
   *   - attestation_count_min, attestation_count_max: attestation count range
   *   - created_after, created_before: creation date range (ISO 8601)
   *   - expires_after, expires_before: expiration date range (ISO 8601)
   *   - <field>[gte]/[lte]/[gt]/[lt]/[regex]: advanced per-field operators
   *     (e.g. attestation_count[gte]=2, issuer[regex]=BANK.*, supports
   *     dotted metadata paths like metadata[name][regex]=...)
   *   - filter[and]/[or]/[not]: nested boolean combinations of the above
   *   - deduplicate: when true, collapses same subject+issuer credentials to
   *     the highest version (ties broken by latest updated_at)
   *   - include_versions: when true, includes a `versions` map of every
   *     subject+issuer group in the response
   *   - include_score: when true, attaches a `reputation_score` to each result
   *   - cursor: base64-encoded cursor for pagination (from previous response)
   *   - limit: results per page (default: 20, max: 100)
   *   - sort_by: comma-separated list of id|type|relevance|created_at|
   *     updated_at|recency|reputation (default: relevance if `q` is set,
   *     otherwise id)
   *   - sort_order: asc|desc (default: desc for recency/reputation, else asc)
   *   - facets: comma-separated facet names (default: issuer,credential_type,status,issuer_type,jurisdiction)
   */
  router.get('/search', credentialQueryFilterMiddleware, async (req: Request, res: Response) => {
    try {
      // Populate index on first search or if empty
      if (currentIndex.getIndexSize() === 0) {
        await populateIndex();
      }

      const {
        q,
        type,
        issuer,
        issuer_type,
        subject,
        status,
        jurisdiction,
        attestation_count_min,
        attestation_count_max,
        created_after,
        created_before,
        expires_after,
        expires_before,
        cursor: cursorQ,
        limit: limitQ = '20',
        facets: facetsQ,
        deduplicate: deduplicateQ,
        show_all: showAllQ,
        include_versions: includeVersionsQ,
        include_score: includeScoreQ,
      } = req.query as Record<string, string>;

      // Validate limit
      const limitNum = parseInt(limitQ, 10);
      if (isNaN(limitNum) || limitNum < 1 || limitNum > 100) {
        res.status(400).json({ error: 'limit must be between 1 and 100' });
        return;
      }

      // sort_by defaults to 'relevance' when a text query is present (so
      // matches rank by relevance instead of arbitrary id order), else 'id'.
      const sortByRaw =
        typeof req.query.sort_by === 'string' && req.query.sort_by.length > 0
          ? req.query.sort_by
          : q
            ? 'relevance'
            : 'id';
      const sortByParts = sortByRaw
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);
      if (sortByParts.length === 0 || !sortByParts.every(p => VALID_SORT_KEYS.includes(p))) {
        res.status(400).json({ error: `sort_by must be one of: ${VALID_SORT_KEYS.join(', ')}` });
        return;
      }

      // recency/reputation naturally mean "best/most-recent first"; default
      // to desc for those unless the caller explicitly asked for asc.
      const sortOrderRaw = typeof req.query.sort_order === 'string' ? req.query.sort_order : undefined;
      const sortOrder =
        sortOrderRaw ?? (sortByParts[0] === 'recency' || sortByParts[0] === 'reputation' ? 'desc' : 'asc');
      if (!['asc', 'desc'].includes(sortOrder)) {
        res.status(400).json({ error: 'sort_order must be "asc" or "desc"' });
        return;
      }

      // Parse facets
      const facets = (facetsQ || 'issuer,credential_type,status,issuer_type,jurisdiction').split(',').map(f => f.trim());

      // Build search options
      const options: SearchOptions = {
        query: q,
        cursor: cursorQ,
        limit: limitNum,
        sort_by: sortByRaw,
        sort_order: sortOrder as 'asc' | 'desc',
        facets,
        filterTree: parseFilterTree(req.query as Record<string, unknown>),
        deduplicate: deduplicateQ === 'true' && showAllQ !== 'true',
        include_versions: includeVersionsQ === 'true',
        include_score: includeScoreQ === 'true',
      };

      // Parse type filter (can be multiple)
      if (type) {
        const types = Array.isArray(type) ? type : [type];
        options.type = types.map(t => parseInt(t, 10)).filter(t => !isNaN(t));
        if (options.type.length === 1) {
          options.type = options.type[0];
        }
      }

      // Parse issuer filter (can be multiple)
      if (issuer) {
        options.issuer = Array.isArray(issuer) ? issuer : [issuer];
        if ((options.issuer as string[]).length === 1) {
          options.issuer = (options.issuer as string[])[0];
        }
      }

      // Parse issuer_type filter (can be multiple)
      if (issuer_type) {
        options.issuer_type = Array.isArray(issuer_type) ? issuer_type : [issuer_type];
        if ((options.issuer_type as string[]).length === 1) {
          options.issuer_type = (options.issuer_type as string[])[0];
        }
      }

      // Parse jurisdiction filter (can be multiple)
      if (jurisdiction) {
        options.jurisdiction = Array.isArray(jurisdiction) ? jurisdiction : [jurisdiction];
        if ((options.jurisdiction as string[]).length === 1) {
          options.jurisdiction = (options.jurisdiction as string[])[0];
        }
      }

      if (subject) options.subject = subject;
      if (status) options.status = status as 'active' | 'revoked' | 'suspended';
      if (attestation_count_min) options.attestation_count_min = parseInt(attestation_count_min, 10);
      if (attestation_count_max) options.attestation_count_max = parseInt(attestation_count_max, 10);
      if (created_after) options.created_after = created_after;
      if (created_before) options.created_before = created_before;
      if (expires_after) options.expires_after = expires_after;
      if (expires_before) options.expires_before = expires_before;

      // Execute search
      const result = currentIndex.search(options);

      res.json({
        data: result.data,
        facets: result.facets,
        pagination: result.pagination,
        query_info: result.query_info,
        index_version: indexVersion,
        ...(result.deduplication_stats && { deduplication_stats: result.deduplication_stats }),
        ...(result.versions && { versions: result.versions }),
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  /**
   * POST /api/credentials/search/rebuild-index-async
   * Kicks off a background full re-scan of the chain into a fresh index,
   * then atomically swaps it in — the current index stays live and
   * queryable for the whole rebuild. Returns immediately with a rebuild ID.
   */
  router.post('/search/rebuild-index-async', (_req: Request, res: Response) => {
    const estimatedDurationMs = Math.max(50, currentIndex.getIndexSize() * 5);

    const job = rebuildManager.start(estimatedDurationMs, async onProgress => {
      const newIndex = new SearchIndex();
      const credCount: bigint = await soroban.simulateCall('get_credential_count', []);
      const total = Number(credCount);
      const totalForProgress = isNaN(total) ? 0 : total;
      let processed = 0;

      for (let i = 1; i <= total; i++) {
        try {
          const cred = await soroban.simulateCall('get_credential', [soroban.u64Val(i)]);
          const credRecord = serializeBigInt(cred) as CredentialRecord;
          credRecord.id = String(credRecord.id || i);
          store.set(credRecord);
          newIndex.indexCredential(credRecord);
        } catch {
          // skip missing/expired credentials
        }
        processed++;
        onProgress(processed, totalForProgress);
      }

      currentIndex = newIndex;
      indexVersion++;
      return newIndex.getIndexSize();
    });

    if (!job) {
      res.status(409).json({ error: 'A rebuild is already in progress' });
      return;
    }

    res.status(202).json({
      rebuild_id: job.rebuild_id,
      status: job.status,
      estimated_duration_ms: job.estimated_duration_ms,
    });
  });

  /**
   * GET /api/credentials/search/rebuild-status/:id
   */
  router.get('/search/rebuild-status/:id', (req: Request, res: Response) => {
    const job = rebuildManager.getStatus(req.params.id);
    if (!job) {
      res.status(404).json({ error: 'Rebuild not found' });
      return;
    }
    res.json(job);
  });

  /**
   * GET /api/credentials/search/rebuild-history
   */
  router.get('/search/rebuild-history', (_req: Request, res: Response) => {
    res.json({ rebuilds: rebuildManager.getHistory() });
  });

  /**
   * POST /api/credentials/verify-batch
   * Body: { credential_ids: number[], slice_id: number }
   * Returns array of { credential_id, attested } results.
   */
  router.post('/verify-batch', async (req: Request, res: Response) => {
    const { credential_ids, slice_id } = req.body as {
      credential_ids?: unknown;
      slice_id?: unknown;
    };

    if (!Array.isArray(credential_ids) || credential_ids.length === 0) {
      res.status(400).json({ error: 'credential_ids must be a non-empty array' });
      return;
    }
    if (typeof slice_id !== 'number' || !Number.isInteger(slice_id) || slice_id <= 0) {
      res.status(400).json({ error: 'slice_id must be a positive integer' });
      return;
    }
    if (credential_ids.length > 50) {
      res.status(400).json({ error: 'credential_ids cannot exceed 50 items' });
      return;
    }
    for (const id of credential_ids) {
      if (typeof id !== 'number' || !Number.isInteger(id) || id <= 0) {
        res.status(400).json({ error: `Invalid credential_id: ${id}` });
        return;
      }
    }

    const results = await Promise.all(
      (credential_ids as number[]).map(async (credential_id) => {
        try {
          const attested: boolean = await soroban.simulateCall('is_attested', [
            soroban.u64Val(credential_id),
            soroban.u64Val(slice_id),
          ]);
          return { credential_id, attested: Boolean(attested), error: null };
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          return { credential_id, attested: false, error: msg };
        }
      })
    );

    res.json({ results: serializeBigInt(results) });
  });

  /**
   * POST /api/credentials/search/refresh-index
   * Force refresh of the search index from blockchain
   */
  router.post('/search/refresh-index', async (req: Request, res: Response) => {
    try {
      metadataHashCache.invalidateAll();
      shardedStore.clear();
      await populateIndex();
      res.json({
        success: true,
        index_size: currentIndex.getIndexSize(),
        cache_size: metadataHashCache.size,
        last_indexed: currentIndex.getLastIndexed(),
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  /**
   * GET /api/credentials/search/index-stats
   * Get search index and metadata hash cache statistics
   */
  router.get('/search/index-stats', (_req: Request, res: Response) => {
    res.json({
      index_size: currentIndex.getIndexSize(),
      vocabulary_size: currentIndex.getVocabularySize(),
      cache_size: metadataHashCache.size,
      last_indexed: currentIndex.getLastIndexed(),
      index_version: indexVersion,
      timestamp: new Date().toISOString(),
    });
  });

  /**
   * GET /api/credentials/crl
   * #866 — Export revoked credentials as a CRL in X.509-compatible JSON structure.
   * Query params:
   *   - issuer: CRL issuer identifier (default: "QuorumProof")
   *   - format: "json" (default) | "pem" (base64-encoded JSON in PEM envelope)
   */
  router.get('/crl', async (req: Request, res: Response) => {
    const issuerName = typeof req.query.issuer === 'string' ? req.query.issuer : 'QuorumProof';
    const format = typeof req.query.format === 'string' ? req.query.format : 'json';

    if (!['json', 'pem'].includes(format)) {
      res.status(400).json({ error: 'format must be "json" or "pem"' });
      return;
    }

    try {
      const credCount: bigint = await soroban.simulateCall('get_credential_count', []);
      const total = Number(credCount);

      const revokedCertificates: Array<{
        serialNumber: string;
        revocationDate: string;
        reason: string;
      }> = [];

      for (let i = 1; i <= total; i++) {
        try {
          const cred = await soroban.simulateCall('get_credential', [soroban.u64Val(i)]);
          const record = serializeBigInt(cred) as CredentialRecord;
          if (record.revoked) {
            revokedCertificates.push({
              serialNumber: String(record.id || i),
              revocationDate: record.updated_at ?? new Date().toISOString(),
              reason: 'unspecified',
            });
          }
        } catch {
          // skip inaccessible credentials
        }
      }

      const thisUpdate = new Date().toISOString();
      const nextUpdateDate = new Date();
      nextUpdateDate.setUTCDate(nextUpdateDate.getUTCDate() + 7);

      const crl = {
        version: 2,
        issuer: issuerName,
        thisUpdate,
        nextUpdate: nextUpdateDate.toISOString(),
        revokedCertificates,
        totalRevoked: revokedCertificates.length,
      };

      if (format === 'pem') {
        const b64 = Buffer.from(JSON.stringify(crl)).toString('base64');
        const lines = b64.match(/.{1,64}/g) ?? [];
        const pem = ['-----BEGIN X509 CRL-----', ...lines, '-----END X509 CRL-----'].join('\n');
        res.type('text/plain').send(pem);
        return;
      }

      res.json(crl);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  /**
   * GET /api/credentials/shards/stats
   * #867 — Return sharded storage distribution statistics.
   */
  router.get('/shards/stats', (_req: Request, res: Response) => {
    res.json({
      shard_count: shardedStore.shardCount,
      total_credentials: shardedStore.totalSize,
      shards: shardedStore.getShardStats(),
    });
  });

  /**
   * GET /api/credentials/shards/by-subject
   * #867 — Fetch credentials for a subject address directly from its shard.
   * Query params:
   *   - subject: subject Stellar address (required)
   */
  router.get('/shards/by-subject', (_req: Request, res: Response) => {
    const { subject } = _req.query;
    if (!subject || typeof subject !== 'string') {
      res.status(400).json({ error: 'subject query parameter required' });
      return;
    }
    const credentials = shardedStore.getBySubject(subject);
    res.json({
      subject,
      shard_index: shardedStore.getShardIndex(subject),
      count: credentials.length,
      credentials,
    });
  });

  /**
   * GET /api/credentials/:id/metadata-hash
   * Returns the cached metadata hash for a credential, fetching from chain if needed.
   */
  router.get('/:id/metadata-hash', async (req: Request, res: Response) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) {
      res.status(400).json({ error: 'Invalid credential ID' });
      return;
    }

    const cached = metadataHashCache.get(String(id));
    if (cached) {
      res.json({ credential_id: id, metadata_hash: cached.metadata_hash, cached: true });
      return;
    }

    try {
      const cred = await soroban.simulateCall('get_credential', [soroban.u64Val(id)]);
      const record = serializeBigInt(cred) as CredentialRecord;
      metadataHashCache.set(String(id), record.metadata_hash, cred as Record<string, unknown>);
      res.json({ credential_id: id, metadata_hash: record.metadata_hash, cached: false });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('CredentialNotFound') || msg.includes('not found')) {
        res.status(404).json({ error: 'Credential not found' });
      } else {
        res.status(500).json({ error: msg });
      }
    }
  });

  return router;
}

// Default export using real soroban client
import { simulateCall, u64Val, u32Val, addressVal } from '../soroban.js';
export default createCredentialsRouter({
  simulateCall,
  u64Val: u64Val as SorobanClient['u64Val'],
  u32Val: u32Val as SorobanClient['u32Val'],
  addressVal: addressVal as SorobanClient['addressVal'],
});
