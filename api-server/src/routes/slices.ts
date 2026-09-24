import { Router, Request, Response } from 'express';
import type { simulateCall as SimulateCallType } from '../soroban.js';
import { respondNegotiated } from '../middleware/contentNegotiation.js';
import {
  SliceVerificationCache,
  getDefaultSliceVerificationCache,
  type SliceCacheMetrics,
} from '../services/sliceVerificationCache.js';

export type SorobanClient = {
  simulateCall: typeof SimulateCallType;
  u64Val: (n: number | bigint) => any;
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

export function createSlicesRouter(
  soroban: SorobanClient,
  cache: SliceVerificationCache = getDefaultSliceVerificationCache(),
) {
  const router = Router();

  /**
   * GET /api/slices/:id
   * Returns a single quorum slice by ID.
   * Results are served from the slice verification cache when possible
   * (Issue #1565) — cache entries expire after SLICE_CACHE_TTL_MS (default
   * 60 s) and can be bypassed with `?bypass_cache=1` for debugging.
   */
  router.get('/:id', async (req: Request, res: Response) => {
    const id = parseInt(req.params.id as string, 10);
    if (!Number.isInteger(id) || id <= 0) {
      res.status(400).json({ error: 'Invalid slice ID' });
      return;
    }

    const bypassCache = req.query.bypass_cache === '1';

    if (!bypassCache) {
      const cached = cache.get(id);
      if (cached !== undefined) {
        res.setHeader('X-Cache', 'HIT');
        res.json(cached);
        return;
      }
    }

    try {
      const slice = await soroban.simulateCall('get_slice', [soroban.u64Val(id)]);
      const serialized = serializeBigInt(slice);
      cache.set(id, serialized);
      res.setHeader('X-Cache', 'MISS');
      res.json(serialized);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('SliceNotFound') || msg.includes('not found')) {
        res.status(404).json({ error: 'Slice not found' });
      } else {
        res.status(500).json({ error: msg });
      }
    }
  });

  /**
   * GET /api/slices?cursor=<base64>&limit=20
   * Returns cursor-paginated list of quorum slices.
   * Individual slice entries are served from / written to the cache.
   */
  router.get('/', async (req: Request, res: Response) => {
    const cursorQ = req.query.cursor ? String(req.query.cursor) : undefined;
    const limit = Math.min(100, Math.max(1, parseInt(String(req.query.limit ?? '20'), 10) || 20));
    const bypassCache = req.query.bypass_cache === '1';

    let startId = 1;
    if (cursorQ) {
      try {
        const decoded = Buffer.from(cursorQ, 'base64').toString('utf-8');
        startId = parseInt(decoded, 10) + 1;
        if (isNaN(startId) || startId < 1) startId = 1;
      } catch {
        res.status(400).json({ error: 'Invalid cursor' });
        return;
      }
    }

    try {
      const sliceCount: bigint = await soroban.simulateCall('get_slice_count', []);
      const total = Number(sliceCount);
      const end = Math.min(startId + limit - 1, total);

      const slices = [];
      for (let i = startId; i <= end; i++) {
        try {
          // Attempt cache lookup for each slice in the page.
          if (!bypassCache) {
            const cached = cache.get(i);
            if (cached !== undefined) {
              slices.push(cached);
              continue;
            }
          }

          const slice = await soroban.simulateCall('get_slice', [soroban.u64Val(i)]);
          const serialized = serializeBigInt(slice);
          cache.set(i, serialized);
          slices.push(serialized);
        } catch {
          // skip missing slices
        }
      }

      const hasMore = end < total;
      const nextCursor = hasMore && slices.length > 0
        ? Buffer.from(String(end)).toString('base64')
        : null;

      const payload = {
        data: slices,
        pagination: {
          cursor: cursorQ ?? null,
          next_cursor: nextCursor,
          limit,
          total,
          has_more: hasMore,
        },
      };
      respondNegotiated(req, res, payload, { rootElement: 'slices', itemElement: 'slice' });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  /**
   * POST /api/slices/:id/invalidate-cache
   * Manually invalidate the cached result for a specific slice.
   * Intended for operator use after administrative slice mutations that
   * bypass the normal write path (e.g. direct contract calls).
   */
  router.post('/:id/invalidate-cache', (req: Request, res: Response) => {
    const id = parseInt(req.params.id as string, 10);
    if (!Number.isInteger(id) || id <= 0) {
      res.status(400).json({ error: 'Invalid slice ID' });
      return;
    }
    cache.invalidate(id);
    res.json({ invalidated: true, sliceId: id });
  });

  /**
   * GET /api/slices/cache/metrics
   * Returns cache performance metrics (hits, misses, invalidations, evictions).
   * Issue #1565 — add cache metrics.
   */
  router.get('/cache/metrics', (_req: Request, res: Response) => {
    const metrics: SliceCacheMetrics = cache.getMetrics();
    res.json(metrics);
  });

  return router;
}

// Default export using real soroban client
import { simulateCall, u64Val } from '../soroban.js';
export default createSlicesRouter({ simulateCall, u64Val: u64Val as SorobanClient['u64Val'] });
