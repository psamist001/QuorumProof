/**
 * SBT Reverse Index Service — Issue #1564
 *
 * The Soroban SBT Registry contract already maintains an on-chain
 * `OwnerTokens(Address)` reverse index (maintained by mint/burn/recover),
 * and exposes it as `get_tokens_by_owner` / `get_tokens_by_holder`.
 *
 * This service provides a server-side cache layer on top of that index so
 * that hot holder lookups never block on an RPC round-trip.  It also exposes
 * consistency checking utilities that can detect drift between the local
 * cache and the authoritative on-chain state, and a one-shot migration
 * helper that pre-warms the index by walking every existing SBT token.
 *
 * Architecture:
 *   holder address (string) → Set<sbt_id (number)>
 *
 * The index is lazily populated on first lookup and refreshed on demand.
 * All writes are applied to both the local index and (via the caller) the
 * on-chain contract.
 */

export interface SbtReverseIndexEntry {
  holder: string;
  sbtIds: number[];
  lastSyncedAt: number | null;
}

export interface ConsistencyReport {
  holder: string;
  localIds: number[];
  chainIds: number[];
  missingFromLocal: number[];
  extraInLocal: number[];
  isConsistent: boolean;
}

export interface MigrationResult {
  holdersProcessed: number;
  sbtsIndexed: number;
  errors: string[];
}

/**
 * In-process holder → SBT-IDs reverse index with TTL-controlled staleness.
 */
export class SbtReverseIndexService {
  /** holder address → set of sbt_id */
  private readonly index: Map<string, Set<number>>;
  /** holder address → last sync timestamp */
  private readonly syncTimes: Map<string, number>;
  private readonly ttlMs: number;

  constructor(options?: { ttlMs?: number }) {
    this.index = new Map();
    this.syncTimes = new Map();
    // Default: cached holder→SBT lists are considered fresh for 5 minutes.
    this.ttlMs = options?.ttlMs ?? 5 * 60_000;
  }

  // ── Index maintenance ───────────────────────────────────────────────────

  /**
   * Record a new SBT being minted to `holder`.
   * Call this on every successful mint so the local index stays current.
   */
  onMint(holder: string, sbtId: number): void {
    this._getOrCreate(holder).add(sbtId);
  }

  /**
   * Remove an SBT from the holder's local index entry on burn/recovery.
   * Call this whenever a burn or successful recovery transfer is confirmed.
   */
  onBurnOrRecover(oldHolder: string, sbtId: number): void {
    this.index.get(oldHolder)?.delete(sbtId);
  }

  /**
   * Record a successful SBT recovery transfer to a new holder.
   * Removes from old holder's set and adds to new holder's set.
   */
  onRecover(oldHolder: string, newHolder: string, sbtId: number): void {
    this.index.get(oldHolder)?.delete(sbtId);
    this._getOrCreate(newHolder).add(sbtId);
  }

  // ── Index queries ───────────────────────────────────────────────────────

  /**
   * Return the locally-cached SBT IDs for `holder`, or `null` if the entry
   * is absent or stale (caller should then fetch from chain and call `populate`).
   */
  getCached(holder: string): number[] | null {
    const synced = this.syncTimes.get(holder);
    if (synced === undefined) return null;
    if (Date.now() - synced > this.ttlMs) return null;
    const ids = this.index.get(holder);
    return ids ? Array.from(ids) : [];
  }

  /**
   * Overwrite the local entry for `holder` with the freshly fetched chain
   * data.  Stamps `lastSyncedAt` so subsequent `getCached` calls will see
   * the entry as fresh.
   */
  populate(holder: string, chainIds: number[]): void {
    const set = this._getOrCreate(holder);
    set.clear();
    for (const id of chainIds) set.add(id);
    this.syncTimes.set(holder, Date.now());
  }

  /**
   * Returns a full snapshot of the entry for `holder`.
   * Unlike `getCached`, never returns `null` — used by the consistency
   * checker where staleness is handled by comparing against fresh chain data.
   */
  getEntry(holder: string): SbtReverseIndexEntry {
    const ids = this.index.get(holder);
    return {
      holder,
      sbtIds: ids ? Array.from(ids) : [],
      lastSyncedAt: this.syncTimes.get(holder) ?? null,
    };
  }

  // ── Consistency checking ────────────────────────────────────────────────

  /**
   * Compare local state for `holder` against the freshly fetched `chainIds`.
   * Returns a report flagging IDs that are missing from local state or
   * spuriously present — used by the consistency-check endpoint.
   */
  checkConsistency(holder: string, chainIds: number[]): ConsistencyReport {
    const localSet = this.index.get(holder) ?? new Set<number>();
    const chainSet = new Set(chainIds);

    const missingFromLocal = chainIds.filter(id => !localSet.has(id));
    const extraInLocal = Array.from(localSet).filter(id => !chainSet.has(id));

    return {
      holder,
      localIds: Array.from(localSet),
      chainIds,
      missingFromLocal,
      extraInLocal,
      isConsistent: missingFromLocal.length === 0 && extraInLocal.length === 0,
    };
  }

  // ── Migration helper ────────────────────────────────────────────────────

  /**
   * Pre-warm the local index from a full token scan.
   *
   * Callers supply a `fetchToken` callback that retrieves a single SBT's
   * owner address for a given token ID, and the total number of tokens
   * (`tokenCount`) to iterate over.  Tokens that have been burned or are
   * otherwise unavailable should cause `fetchToken` to throw — those are
   * counted as errors but do not abort the migration.
   *
   * In practice you'd call this once on startup against a fresh deployment
   * or after a long outage where local state drifted.
   */
  async migrate(
    tokenCount: number,
    fetchToken: (id: number) => Promise<{ id: number; owner: string } | null>,
  ): Promise<MigrationResult> {
    // Clear existing index so we start from a known-empty state.
    this.index.clear();
    this.syncTimes.clear();

    const holders = new Map<string, Set<number>>();
    const errors: string[] = [];
    let sbtsIndexed = 0;

    for (let i = 1; i <= tokenCount; i++) {
      try {
        const token = await fetchToken(i);
        if (!token) continue;
        const { id, owner } = token;
        if (!holders.has(owner)) holders.set(owner, new Set());
        holders.get(owner)!.add(id);
        sbtsIndexed++;
      } catch (err: unknown) {
        errors.push(`token ${i}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // Commit all gathered data into the index at once.
    const now = Date.now();
    for (const [holder, ids] of holders) {
      this.index.set(holder, ids);
      this.syncTimes.set(holder, now);
    }

    return { holdersProcessed: holders.size, sbtsIndexed, errors };
  }

  // ── Internal helpers ────────────────────────────────────────────────────

  private _getOrCreate(holder: string): Set<number> {
    let set = this.index.get(holder);
    if (!set) {
      set = new Set();
      this.index.set(holder, set);
    }
    return set;
  }

  /** Expose all indexed holders — used by migration/admin tooling. */
  allHolders(): string[] {
    return Array.from(this.index.keys());
  }

  /** Total number of SBT IDs across all holders in the local index. */
  totalIndexedSbts(): number {
    let total = 0;
    for (const ids of this.index.values()) total += ids.size;
    return total;
  }

  /** Remove all local state — for testing. */
  _reset(): void {
    this.index.clear();
    this.syncTimes.clear();
  }
}

// ── Module-level singleton ────────────────────────────────────────────────────

let defaultService: SbtReverseIndexService | undefined;

export function getDefaultSbtReverseIndexService(): SbtReverseIndexService {
  if (!defaultService) {
    const ttlMs = parseInt(process.env.SBT_INDEX_TTL_MS ?? '', 10);
    defaultService = new SbtReverseIndexService({
      ttlMs: Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : undefined,
    });
  }
  return defaultService;
}

export function _setDefaultSbtReverseIndexServiceForTest(
  service: SbtReverseIndexService | undefined,
): void {
  defaultService = service;
}
