/**
 * Gas cost reporting and estimation routes — Issue #4 + Issue #1562.
 *
 * Existing endpoints (Issue #4):
 *   GET /api/costs/report          — aggregated gas cost report
 *   GET /api/costs/optimizations   — ranked optimisation recommendations
 *   GET /api/costs/projection      — project future costs for an operation
 *
 * New endpoint (Issue #1562):
 *   POST /api/costs/estimate-gas   — estimate gas cost for a given operation
 *                                    before submitting a transaction
 *
 * Error responses use the shared RFC 9457 Problem Details formatter.
 */
import { Router, Request, Response } from 'express';
import { getDefaultGasCostTracker } from '../services/gasCostTracker.js';
import { problemJson } from '../middleware/problemDetails.js';

const router = Router();

// ── Fee schedule ──────────────────────────────────────────────────────────────
//
// Static baseline estimates (in stroops) per operation type, used when there
// is no observed data in the gas cost tracker yet.  Values were derived from
// Soroban testnet simulations during development; operators can override them
// via the GAS_FEE_SCHEDULE_* env vars.
//
// One stroop = 1e-7 XLM.  Soroban fees are composed of:
//   - inclusion fee  (BASE_FEE, currently 100 stroops, paid to validators)
//   - resource fee   (CPU/memory/IO instructions × per-unit rate)
//
// The values below capture the resource fee portion only — the inclusion fee
// is charged separately and is constant regardless of operation complexity.

const STROOPS_PER_XLM = 10_000_000n;

function xlmUsdPrice(): number {
  const v = parseFloat(process.env.XLM_USD_PRICE ?? '');
  return Number.isFinite(v) && v > 0 ? v : 0.12;
}

function envFee(envVar: string, fallback: number): number {
  const v = parseInt(process.env[envVar] ?? '', 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

/**
 * Static fee schedule — baseline stroop costs per operation, pre-populated
 * from Soroban testnet observations.
 *
 * Format: operationName → baseFeeStroops
 */
export const FEE_SCHEDULE: Record<string, number> = {
  // Credential lifecycle
  issue_credential:    envFee('GAS_FEE_ISSUE_CREDENTIAL',    25_000),
  get_credential:      envFee('GAS_FEE_GET_CREDENTIAL',       3_000),
  revoke_credential:   envFee('GAS_FEE_REVOKE_CREDENTIAL',   15_000),
  get_credential_count: envFee('GAS_FEE_GET_CREDENTIAL_COUNT', 2_000),

  // Quorum slice management
  create_slice:        envFee('GAS_FEE_CREATE_SLICE',         20_000),
  get_slice:           envFee('GAS_FEE_GET_SLICE',             3_000),
  add_attestor:        envFee('GAS_FEE_ADD_ATTESTOR',         18_000),
  remove_attestor:     envFee('GAS_FEE_REMOVE_ATTESTOR',      18_000),
  get_slice_count:     envFee('GAS_FEE_GET_SLICE_COUNT',       2_000),

  // Attestation
  attest:              envFee('GAS_FEE_ATTEST',               22_000),
  is_attested:         envFee('GAS_FEE_IS_ATTESTED',           3_500),
  get_attestors:       envFee('GAS_FEE_GET_ATTESTORS',         4_000),

  // SBT registry
  mint_sbt:            envFee('GAS_FEE_MINT_SBT',             28_000),
  burn_sbt:            envFee('GAS_FEE_BURN_SBT',             14_000),
  get_sbt:             envFee('GAS_FEE_GET_SBT',               3_000),
  get_token_count:     envFee('GAS_FEE_GET_TOKEN_COUNT',       2_000),
  get_tokens_by_holder: envFee('GAS_FEE_GET_TOKENS_BY_HOLDER',  5_000),

  // ZK verification
  verify_groth16_proof: envFee('GAS_FEE_VERIFY_GROTH16',     120_000),
  verify_plonk_proof:   envFee('GAS_FEE_VERIFY_PLONK',       140_000),
};

/** Inclusion fee in stroops — constant per Soroban transaction. */
const INCLUSION_FEE_STROOPS = 100;

export interface GasEstimate {
  operation: string;
  /** Data source for this estimate: 'observed' (from tracker) or 'schedule' (static baseline). */
  source: 'observed' | 'schedule';
  /** Number of observed calls this estimate is based on (0 when source is 'schedule'). */
  sample_size: number;
  /** Estimated resource fee in stroops. */
  resource_fee_stroops: number;
  /** Constant inclusion fee in stroops. */
  inclusion_fee_stroops: number;
  /** Total estimated fee in stroops. */
  total_fee_stroops: number;
  /** Total estimated fee in XLM. */
  total_fee_xlm: number;
  /** Total estimated fee in USD (at configured XLM/USD price). */
  total_fee_usd: number;
  /** Current XLM/USD price used. */
  xlm_usd_price: number;
  /** Confidence level: high (≥50 samples), medium (10–49), low (<10 or schedule-only). */
  confidence: 'high' | 'medium' | 'low';
}

function confidenceLevel(sampleSize: number, source: 'observed' | 'schedule'): 'high' | 'medium' | 'low' {
  if (source === 'schedule') return 'low';
  if (sampleSize >= 50) return 'high';
  if (sampleSize >= 10) return 'medium';
  return 'low';
}

function stroopsToXlm(stroops: number): number {
  return stroops / Number(STROOPS_PER_XLM);
}

/**
 * Build a gas estimate for a single operation.
 * Prefers observed average from the tracker; falls back to the static
 * fee schedule if no data has been recorded yet.
 */
function buildEstimate(operation: string): GasEstimate | null {
  const tracker = getDefaultGasCostTracker();
  const report = tracker.getReport();
  const observed = report.byOperation.find(op => op.operation === operation);

  const price = xlmUsdPrice();

  if (observed && observed.callCount > 0) {
    const resourceFee = Number(BigInt(observed.avgStroops));
    const total = resourceFee + INCLUSION_FEE_STROOPS;
    const totalXlm = stroopsToXlm(total);
    return {
      operation,
      source: 'observed',
      sample_size: observed.callCount,
      resource_fee_stroops: resourceFee,
      inclusion_fee_stroops: INCLUSION_FEE_STROOPS,
      total_fee_stroops: total,
      total_fee_xlm: totalXlm,
      total_fee_usd: totalXlm * price,
      xlm_usd_price: price,
      confidence: confidenceLevel(observed.callCount, 'observed'),
    };
  }

  const scheduleFee = FEE_SCHEDULE[operation];
  if (scheduleFee === undefined) return null;

  const total = scheduleFee + INCLUSION_FEE_STROOPS;
  const totalXlm = stroopsToXlm(total);
  return {
    operation,
    source: 'schedule',
    sample_size: 0,
    resource_fee_stroops: scheduleFee,
    inclusion_fee_stroops: INCLUSION_FEE_STROOPS,
    total_fee_stroops: total,
    total_fee_xlm: totalXlm,
    total_fee_usd: totalXlm * price,
    xlm_usd_price: price,
    confidence: 'low',
  };
}

// ── Existing routes (Issue #4) ────────────────────────────────────────────────

// GET /api/costs/report — aggregated gas cost report across all tracked operations
router.get('/report', (_req: Request, res: Response) => {
  res.json(getDefaultGasCostTracker().getReport());
});

// GET /api/costs/optimizations — ranked list of operations worth optimizing
router.get('/optimizations', (req: Request, res: Response) => {
  const topN = parseInt((req.query.top as string) ?? '5', 10);
  res.json({ recommendations: getDefaultGasCostTracker().getOptimizationRecommendations(Number.isFinite(topN) ? topN : 5) });
});

// GET /api/costs/projection?operation=is_attested&callsPerDay=10000&days=30
router.get('/projection', (req: Request, res: Response) => {
  const { operation, callsPerDay, days } = req.query as Record<string, string | undefined>;
  if (!operation) {
    res.status(400).json(problemJson(400, 'missing-parameter', 'operation query param is required'));
    return;
  }
  const parsedCallsPerDay = parseFloat(callsPerDay ?? '');
  const parsedDays = parseFloat(days ?? '30');
  if (!Number.isFinite(parsedCallsPerDay) || parsedCallsPerDay <= 0) {
    res.status(400).json(problemJson(400, 'invalid-parameter', 'callsPerDay must be a positive number'));
    return;
  }

  const projection = getDefaultGasCostTracker().project(operation, parsedCallsPerDay, Number.isFinite(parsedDays) ? parsedDays : 30);
  if (!projection) {
    res.status(404).json(problemJson(404, 'not-found', `No recorded cost data for operation "${operation}" yet`));
    return;
  }
  res.json(projection);
});

// ── New route (Issue #1562) ───────────────────────────────────────────────────

/**
 * POST /api/costs/estimate-gas
 *
 * Estimates the gas (resource fee) cost for one or more Soroban operations
 * before the transaction is submitted.  Useful for UX warnings ("this will
 * cost ~0.0003 XLM") and for tooling that needs to set a sensible fee cap.
 *
 * Request body:
 *   { "operations": ["issue_credential", "attest"] }
 *   — or a single operation string:
 *   { "operation": "issue_credential" }
 *
 * Response:
 *   {
 *     "estimates": [ GasEstimate, ... ],
 *     "totals": { total_fee_stroops, total_fee_xlm, total_fee_usd },
 *     "fee_schedule": { ... }   // full schedule for reference
 *   }
 */
router.post('/estimate-gas', (req: Request, res: Response) => {
  const body = req.body as Record<string, unknown>;

  // Accept either a single operation string or an array.
  let operationNames: string[] = [];
  if (typeof body.operation === 'string' && body.operation.trim()) {
    operationNames = [body.operation.trim()];
  } else if (Array.isArray(body.operations)) {
    operationNames = body.operations
      .filter((o): o is string => typeof o === 'string' && o.trim().length > 0)
      .map(o => o.trim());
  }

  if (operationNames.length === 0) {
    res.status(400).json(
      problemJson(
        400,
        'missing-parameter',
        'Provide "operation" (string) or "operations" (non-empty array of strings) in the request body.',
      ),
    );
    return;
  }

  // Cap to 20 operations per request to prevent abuse.
  const MAX_OPS = 20;
  if (operationNames.length > MAX_OPS) {
    res.status(400).json(
      problemJson(400, 'invalid-parameter', `At most ${MAX_OPS} operations per request.`),
    );
    return;
  }

  // Validate operation name format — alphanumeric + underscore only.
  const invalidName = operationNames.find(n => !/^[a-z][a-z0-9_]{0,63}$/.test(n));
  if (invalidName) {
    res.status(400).json(
      problemJson(
        400,
        'invalid-parameter',
        `Invalid operation name "${invalidName}". Names must be lowercase alphanumeric with underscores (max 64 chars).`,
      ),
    );
    return;
  }

  const estimates: GasEstimate[] = [];
  const unknownOperations: string[] = [];

  for (const name of operationNames) {
    const estimate = buildEstimate(name);
    if (estimate) {
      estimates.push(estimate);
    } else {
      unknownOperations.push(name);
    }
  }

  // If *all* operations are unknown we return 422 Unprocessable Entity.
  if (estimates.length === 0) {
    res.status(422).json(
      problemJson(
        422,
        'unknown-operations',
        `None of the requested operations are in the fee schedule or have observed data: ${unknownOperations.join(', ')}. ` +
          `Known operations: ${Object.keys(FEE_SCHEDULE).join(', ')}.`,
      ),
    );
    return;
  }

  // Aggregate totals across all estimated operations.
  const totalStroops = estimates.reduce((sum, e) => sum + e.total_fee_stroops, 0);
  const price = xlmUsdPrice();
  const totalXlm = stroopsToXlm(totalStroops);

  res.json({
    estimates,
    totals: {
      total_fee_stroops: totalStroops,
      total_fee_xlm: totalXlm,
      total_fee_usd: totalXlm * price,
    },
    ...(unknownOperations.length > 0 && {
      warnings: unknownOperations.map(
        op => `"${op}" is not in the fee schedule and has no observed data — skipped.`,
      ),
    }),
    fee_schedule: FEE_SCHEDULE,
  });
});

/**
 * GET /api/costs/fee-schedule
 * Returns the static fee schedule for all known operations.
 * Useful for clients that want to pre-populate a picker or run their own math.
 */
router.get('/fee-schedule', (_req: Request, res: Response) => {
  const price = xlmUsdPrice();
  const schedule = Object.entries(FEE_SCHEDULE).map(([operation, stroops]) => {
    const total = stroops + INCLUSION_FEE_STROOPS;
    const xlm = stroopsToXlm(total);
    return {
      operation,
      baseline_resource_fee_stroops: stroops,
      inclusion_fee_stroops: INCLUSION_FEE_STROOPS,
      total_fee_stroops: total,
      total_fee_xlm: xlm,
      total_fee_usd: xlm * price,
    };
  });

  res.json({
    schedule,
    xlm_usd_price: price,
    note: 'These are static baseline estimates. POST /api/costs/estimate-gas returns observed averages when available.',
  });
});

export default router;
