/**
 * SBT (Soulbound Token) routes — Issue #1564
 *
 * Provides a server-side reverse index so callers can query "which SBTs does
 * this holder own?" without scanning all tokens.  The on-chain
 * `OwnerTokens(Address)` data key (maintained by mint/burn/recover) is the
 * authoritative source; this service caches the result locally and adds
 * consistency-check and migration endpoints on top.
 *
 * Routes:
 *   GET  /api/sbt/holder/:address         — list SBT IDs for a holder
 *   GET  /api/sbt/holder/:address/check   — consistency check (local vs chain)
 *   POST /api/sbt/index/migrate           — pre-warm index from full token scan
 *   GET  /api/sbt/index/stats             — stats for the local index
 */

import { Router, Request, Response } from 'express';
import type { simulateCall as SimulateCallType } from '../soroban.js';
import {
  SbtReverseIndexService,
  getDefaultSbtReverseIndexService,
} from '../services/sbtReverseIndex.js';

export type SorobanClient = {
  simulateCall: typeof SimulateCallType;
  u64Val: (n: number | bigint) => any;
  addressVal: (a: string) => any;
};

/** Basic Stellar address format validation (G... for public keys). */
function isValidAddress(addr: string): boolean {
  return /^G[A-Z2-7]{55}$/.test(addr);
}

export function createSbtRouter(
  soroban: SorobanClient,
  indexService: SbtReverseIndexService = getDefaultSbtReverseIndexService(),
) {
  const router = Router();

  /**
   * GET /api/sbt/holder/:address
   * Returns all SBT token IDs held by the given Stellar address.
   *
   * Serves from the local reverse index when the entry is fresh; otherwise
   * fetches from the chain via `get_tokens_by_holder` and populates the cache.
   * The `X-Index-Source` response header reports `cache` or `chain`.
   */
  router.get('/holder/:address', async (req: Request, res: Response) => {
    const { address } = req.params;

    if (!address || !isValidAddress(address)) {
      res.status(400).json({ error: 'Invalid Stellar address — expected a G... public key.' });
      return;
    }

    // Attempt cache lookup first.
    const cached = indexService.getCached(address);
    if (cached !== null) {
      res.setHeader('X-Index-Source', 'cache');
      res.json({ holder: address, sbt_ids: cached, count: cached.length });
      return;
    }

    // Cache miss or stale — fetch from chain.
    try {
      const chainResult: bigint[] = await soroban.simulateCall('get_tokens_by_holder', [
        soroban.addressVal(address),
      ]);
      const ids = Array.isArray(chainResult) ? chainResult.map(Number) : [];
      indexService.populate(address, ids);
      res.setHeader('X-Index-Source', 'chain');
      res.json({ holder: address, sbt_ids: ids, count: ids.length });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `Failed to fetch SBT index from chain: ${msg}` });
    }
  });

  /**
   * GET /api/sbt/holder/:address/check
   * Fetches the authoritative chain list and compares it against the local
   * cache, returning a consistency report.
   *
   * Use this to detect drift between the local index and on-chain state —
   * for example after a long downtime or a direct contract write that
   * bypassed the API.
   */
  router.get('/holder/:address/check', async (req: Request, res: Response) => {
    const { address } = req.params;

    if (!address || !isValidAddress(address)) {
      res.status(400).json({ error: 'Invalid Stellar address.' });
      return;
    }

    try {
      const chainResult: bigint[] = await soroban.simulateCall('get_tokens_by_holder', [
        soroban.addressVal(address),
      ]);
      const chainIds = Array.isArray(chainResult) ? chainResult.map(Number) : [];
      const report = indexService.checkConsistency(address, chainIds);
      res.json(report);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `Failed to fetch chain state for consistency check: ${msg}` });
    }
  });

  /**
   * POST /api/sbt/index/migrate
   * Pre-warm the local reverse index by walking every existing SBT token.
   *
   * This is a migration helper — run it once after deploying this service
   * against an existing contract that already has tokens, or after any
   * extended downtime where the local index may have drifted.
   *
   * Returns the number of holders processed and SBTs indexed.
   */
  router.post('/index/migrate', async (_req: Request, res: Response) => {
    try {
      const tokenCount: bigint = await soroban.simulateCall('get_token_count', []);
      const total = Number(tokenCount);

      const result = await indexService.migrate(total, async (id: number) => {
        try {
          const token = await soroban.simulateCall('get_sbt', [soroban.u64Val(id)]);
          if (!token || typeof token !== 'object') return null;
          const t = token as Record<string, unknown>;
          const owner = typeof t.owner === 'string' ? t.owner : String(t.owner ?? '');
          return { id, owner };
        } catch {
          return null;
        }
      });

      res.json({ success: true, ...result });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: `Migration failed: ${msg}` });
    }
  });

  /**
   * GET /api/sbt/index/stats
   * Returns statistics about the local reverse index.
   */
  router.get('/index/stats', (_req: Request, res: Response) => {
    res.json({
      holders: indexService.allHolders().length,
      total_indexed_sbts: indexService.totalIndexedSbts(),
    });
  });

  return router;
}

// Default export using real soroban client
import { simulateCall, u64Val, addressVal } from '../soroban.js';
export default createSbtRouter({
  simulateCall,
  u64Val: u64Val as SorobanClient['u64Val'],
  addressVal: addressVal as SorobanClient['addressVal'],
});
