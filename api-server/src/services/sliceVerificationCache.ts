/**
 * Slice Verification Result Cache — Issue #1565
 *
 * Caches the result of `get_slice` Soroban calls so repeated queries for the
 * same slice ID hit an in-process map instead of the RPC layer.
 *
 * Design decisions:
 * - TTL-based expiry (default 60 s): slices are relatively stable but can be
 *   updated (attestor added/removed, threshold changed), so a short-lived cache
 *   balances latency improvement against stale-read risk.
 * - Per-slice invalidation: when a write path modifies a slice the entry is
 *   evicted immediately instead of waiting for TTL expiry.
 * - LRU-style size cap: the cache holds at most MAX_ENTRIES entries; when full,
 *   the oldest (by insertion order) is evicted to prevent unbounded memory
 *   growth.
 * - Metrics counters: hits, misses, invalidations, and evictions are tracked
 *   so operators can tune TTL and MAX_ENTRIES from observed traffic.
 */

export interface SliceCacheEntry {
  /** Serialised slice value (BigInt-free, ready for JSON.stringify). */
  value: unknown;
  /** Unix-ms timestamp when this entry was stored. */
  storedAt: number;
  /** The slice ID this entry covers. */
  sliceId: number;
}

export interface SliceCacheMetrics {
  hits: number;
  misses: number;
  invalidations: number;
  evictions: number;
  size: number;
  maxSize: number;
  ttlMs: number;
}

/** Default time-to-live for a cached slice result (60 seconds). */
const DEFAULT_TTL_MS = 60_000;

/** Maximum number of entries to hold simultaneously. */
const DEFAULT_MAX_ENTRIES = 1_000;

export class SliceVerificationCache {
  private readonly cache: Map<number, SliceCacheEntry>;
  private readonly ttlMs: number;
  private readonly maxEntries: number;

  private _hits = 0;
  private _misses = 0;
  private _invalidations = 0;
  private _evictions = 0;

  constructor(options?: { ttlMs?: number; maxEntries?: number }) {
    this.ttlMs = options?.ttlMs ?? DEFAULT_TTL_MS;
    this.maxEntries = options?.maxEntries ?? DEFAULT_MAX_ENTRIES;
    // Insertion-ordered Map gives us FIFO eviction for free.
    this.cache = new Map();
  }

  /**
   * Retrieve a cached slice result.
   * Returns `undefined` on a cache miss or if the entry has expired.
   */
  get(sliceId: number): unknown | undefined {
    const entry = this.cache.get(sliceId);
    if (!entry) {
      this._misses++;
      return undefined;
    }

    const age = Date.now() - entry.storedAt;
    if (age > this.ttlMs) {
      // Expired — remove it and report a miss.
      this.cache.delete(sliceId);
      this._misses++;
      return undefined;
    }

    this._hits++;
    return entry.value;
  }

  /**
   * Store a slice result in the cache.
   * If the cache is at capacity, the oldest entry is evicted first.
   */
  set(sliceId: number, value: unknown): void {
    // If the key already exists, deleting then re-inserting keeps Map
    // insertion order representative of recency.
    if (this.cache.has(sliceId)) {
      this.cache.delete(sliceId);
    } else if (this.cache.size >= this.maxEntries) {
      // Evict the oldest entry (first key in insertion order).
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
        this._evictions++;
      }
    }

    this.cache.set(sliceId, { value, storedAt: Date.now(), sliceId });
  }

  /**
   * Invalidate the cached entry for a specific slice.
   * Call this whenever a write operation mutates slice `sliceId`
   * (e.g. add_attestor, remove_attestor, update_threshold).
   */
  invalidate(sliceId: number): void {
    if (this.cache.delete(sliceId)) {
      this._invalidations++;
    }
  }

  /**
   * Invalidate all cached entries.
   * Use when a bulk operation or contract upgrade makes all cached state suspect.
   */
  invalidateAll(): void {
    const count = this.cache.size;
    this.cache.clear();
    this._invalidations += count;
  }

  /**
   * Remove all entries whose TTL has elapsed.
   * Callers may run this on a periodic timer to prevent stale entries
   * from lingering after periods of low traffic.
   */
  purgeExpired(): number {
    const now = Date.now();
    let purged = 0;
    for (const [key, entry] of this.cache) {
      if (now - entry.storedAt > this.ttlMs) {
        this.cache.delete(key);
        purged++;
      }
    }
    return purged;
  }

  /** Returns a snapshot of cache performance metrics. */
  getMetrics(): SliceCacheMetrics {
    return {
      hits: this._hits,
      misses: this._misses,
      invalidations: this._invalidations,
      evictions: this._evictions,
      size: this.cache.size,
      maxSize: this.maxEntries,
      ttlMs: this.ttlMs,
    };
  }

  /** Reset metrics counters — for testing. */
  _resetMetrics(): void {
    this._hits = 0;
    this._misses = 0;
    this._invalidations = 0;
    this._evictions = 0;
  }
}

// ── Module-level singleton ────────────────────────────────────────────────────

let defaultCache: SliceVerificationCache | undefined;

export function getDefaultSliceVerificationCache(): SliceVerificationCache {
  if (!defaultCache) {
    const ttlMs = parseInt(process.env.SLICE_CACHE_TTL_MS ?? String(DEFAULT_TTL_MS), 10);
    const maxEntries = parseInt(process.env.SLICE_CACHE_MAX_ENTRIES ?? String(DEFAULT_MAX_ENTRIES), 10);
    defaultCache = new SliceVerificationCache({
      ttlMs: Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : DEFAULT_TTL_MS,
      maxEntries: Number.isFinite(maxEntries) && maxEntries > 0 ? maxEntries : DEFAULT_MAX_ENTRIES,
    });
  }
  return defaultCache;
}

export function _setDefaultSliceCacheForTest(cache: SliceVerificationCache | undefined): void {
  defaultCache = cache;
}
