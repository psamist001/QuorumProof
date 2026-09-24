/**
 * Tests for Gas Cost Reporting and Estimation Routes — Issue #1440 / #4 / #1562
 *
 * Covers:
 *  - GET /api/costs/report (empty report, aggregated operation statistics, XLM/USD conversion)
 *  - GET /api/costs/optimizations (valid top=N, invalid N fallback, recommendations format)
 *  - GET /api/costs/projection (missing operation 400, invalid callsPerDay 400, 404 for unrecorded operations, happy-path calculations)
 *  - POST /api/costs/estimate-gas (single op, multi-op, observed vs schedule source, validation, unknown ops — Issue #1562)
 *  - GET /api/costs/fee-schedule (static schedule listing — Issue #1562)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import costsRouter from '../src/routes/costs.js';
import {
  GasCostTracker,
  _setDefaultGasCostTrackerForTest,
} from '../src/services/gasCostTracker.js';

describe('Gas Cost Routes (/api/costs)', () => {
  let app: express.Express;
  let tempDir: string;
  let tracker: GasCostTracker;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'costs-test-'));
    process.env.XLM_USD_PRICE = '0.15';

    tracker = new GasCostTracker(tempDir);
    _setDefaultGasCostTrackerForTest(tracker);

    app = express();
    app.use(express.json());
    app.use('/api/costs', costsRouter);
  });

  afterEach(() => {
    try {
      if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    } catch {
      // Best-effort cleanup
    }
    _setDefaultGasCostTrackerForTest(undefined);
    delete process.env.XLM_USD_PRICE;
  });

  // ---------------------------------------------------------------------------
  // 1. GET /api/costs/report
  // ---------------------------------------------------------------------------
  describe('GET /api/costs/report', () => {
    it('returns default empty report when no operations have been recorded', async () => {
      const res = await request(app).get('/api/costs/report');

      expect(res.status).toBe(200);
      expect(res.body.generatedAt).toBeDefined();
      expect(res.body.xlmUsdPrice).toBe(0.15);
      expect(res.body.totalCalls).toBe(0);
      expect(res.body.totalStroops).toBe('0');
      expect(res.body.totalXlm).toBe(0);
      expect(res.body.totalUsd).toBe(0);
      expect(res.body.byOperation).toEqual([]);
    });

    it('returns aggregated gas cost report with correct calculations and sorting', async () => {
      // 10,000,000 stroops = 1 XLM
      tracker.record('is_attested', '10000000');
      tracker.record('is_attested', '30000000'); // total 40,000,000 stroops = 4 XLM, avg 20,000,000
      tracker.record('issue_credential', '100000000'); // 100,000,000 stroops = 10 XLM
      tracker.record('revoke_credential', '20000000'); // 20,000,000 stroops = 2 XLM

      const res = await request(app).get('/api/costs/report');

      expect(res.status).toBe(200);
      expect(res.body.totalCalls).toBe(4);
      expect(res.body.totalStroops).toBe('160000000'); // 160M stroops = 16 XLM
      expect(res.body.totalXlm).toBe(16);
      expect(res.body.totalUsd).toBeCloseTo(16 * 0.15, 4);

      // Operations must be sorted by totalStroops descending
      expect(res.body.byOperation).toHaveLength(3);
      expect(res.body.byOperation[0].operation).toBe('issue_credential');
      expect(res.body.byOperation[0].callCount).toBe(1);
      expect(res.body.byOperation[0].totalStroops).toBe('100000000');

      expect(res.body.byOperation[1].operation).toBe('is_attested');
      expect(res.body.byOperation[1].callCount).toBe(2);
      expect(res.body.byOperation[1].totalStroops).toBe('40000000');
      expect(res.body.byOperation[1].minStroops).toBe('10000000');
      expect(res.body.byOperation[1].maxStroops).toBe('30000000');
      expect(res.body.byOperation[1].avgStroops).toBe('20000000');

      expect(res.body.byOperation[2].operation).toBe('revoke_credential');
      expect(res.body.byOperation[2].callCount).toBe(1);
      expect(res.body.byOperation[2].totalStroops).toBe('20000000');
    });
  });

  // ---------------------------------------------------------------------------
  // 2. GET /api/costs/optimizations
  // ---------------------------------------------------------------------------
  describe('GET /api/costs/optimizations', () => {
    it('returns empty recommendations when no operations are recorded', async () => {
      const res = await request(app).get('/api/costs/optimizations');

      expect(res.status).toBe(200);
      expect(res.body.recommendations).toEqual([]);
    });

    it('returns ranked recommendations with valid top=N parameter', async () => {
      tracker.record('verify_batch', '500000000'); // 50 XLM (heavy contribution)
      tracker.record('issue_credential', '100000000');
      tracker.record('is_attested', '10000000');

      const res = await request(app).get('/api/costs/optimizations?top=2');

      expect(res.status).toBe(200);
      expect(res.body.recommendations).toHaveLength(2);
      expect(res.body.recommendations[0].operation).toBe('verify_batch');
      expect(res.body.recommendations[0].totalXlmContribution).toBe(50);
      expect(res.body.recommendations[0].reason).toContain('Accounts for');
      expect(res.body.recommendations[1].operation).toBe('issue_credential');
    });

    it('falls back gracefully to default top=5 when top query param is non-numeric or invalid', async () => {
      tracker.record('op1', '10000000');
      tracker.record('op2', '20000000');

      const res = await request(app).get('/api/costs/optimizations?top=invalid-value');

      expect(res.status).toBe(200);
      expect(res.body.recommendations).toBeInstanceOf(Array);
      expect(res.body.recommendations.length).toBeLessThanOrEqual(5);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. GET /api/costs/projection
  // ---------------------------------------------------------------------------
  describe('GET /api/costs/projection', () => {
    it('returns 400 when operation query parameter is missing', async () => {
      const res = await request(app).get('/api/costs/projection?callsPerDay=1000&days=30');

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('operation query param is required');
    });

    it('returns 400 when callsPerDay is missing or not a positive number', async () => {
      const missingCalls = await request(app).get('/api/costs/projection?operation=is_attested');
      expect(missingCalls.status).toBe(400);
      expect(missingCalls.body.error).toBe('callsPerDay must be a positive number');

      const zeroCalls = await request(app).get('/api/costs/projection?operation=is_attested&callsPerDay=0');
      expect(zeroCalls.status).toBe(400);
      expect(zeroCalls.body.error).toBe('callsPerDay must be a positive number');

      const negativeCalls = await request(app).get('/api/costs/projection?operation=is_attested&callsPerDay=-50');
      expect(negativeCalls.status).toBe(400);
      expect(negativeCalls.body.error).toBe('callsPerDay must be a positive number');

      const nonNumericCalls = await request(app).get('/api/costs/projection?operation=is_attested&callsPerDay=abc');
      expect(nonNumericCalls.status).toBe(400);
      expect(nonNumericCalls.body.error).toBe('callsPerDay must be a positive number');
    });

    it('returns 404 when operation has no recorded cost data', async () => {
      const res = await request(app).get('/api/costs/projection?operation=non_existent_op&callsPerDay=1000&days=30');

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('No recorded cost data for operation "non_existent_op" yet');
    });

    it('calculates cost projection correctly on happy path with custom days', async () => {
      // 10,000,000 stroops (1 XLM) avg per call
      tracker.record('is_attested', '10000000');

      // 1,000 calls/day * 30 days = 30,000 calls
      // 30,000 calls * 10,000,000 stroops = 300,000,000,000 stroops = 30,000 XLM
      // 30,000 XLM * $0.15 = $4,500 USD
      const res = await request(app).get('/api/costs/projection?operation=is_attested&callsPerDay=1000&days=30');

      expect(res.status).toBe(200);
      expect(res.body.operation).toBe('is_attested');
      expect(res.body.callsPerDay).toBe(1000);
      expect(res.body.days).toBe(30);
      expect(res.body.basedOnAvgStroops).toBe('10000000');
      expect(res.body.projectedStroops).toBe('300000000000');
      expect(res.body.projectedXlm).toBe(30000);
      expect(res.body.projectedUsd).toBeCloseTo(4500, 2);
    });

    it('defaults days to 30 when days parameter is omitted', async () => {
      tracker.record('is_attested', '10000000');

      const res = await request(app).get('/api/costs/projection?operation=is_attested&callsPerDay=500');

      expect(res.status).toBe(200);
      expect(res.body.days).toBe(30);
      expect(res.body.projectedXlm).toBe(15000);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. POST /api/costs/estimate-gas  (Issue #1562)
  // ---------------------------------------------------------------------------
  describe('POST /api/costs/estimate-gas', () => {
    it('returns 400 when neither operation nor operations is provided', async () => {
      const res = await request(app).post('/api/costs/estimate-gas').send({});
      expect(res.status).toBe(400);
    });

    it('returns 400 when operations array is empty', async () => {
      const res = await request(app).post('/api/costs/estimate-gas').send({ operations: [] });
      expect(res.status).toBe(400);
    });

    it('returns 400 when operations array exceeds 20 entries', async () => {
      const ops = Array.from({ length: 21 }, (_, i) => `issue_credential`);
      const res = await request(app).post('/api/costs/estimate-gas').send({ operations: ops });
      expect(res.status).toBe(400);
    });

    it('returns 400 when an operation name contains invalid characters', async () => {
      const res = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operation: 'drop table; --' });
      expect(res.status).toBe(400);
    });

    it('returns 422 when all operations are unknown', async () => {
      const res = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operations: ['totally_unknown_op'] });
      expect(res.status).toBe(422);
      expect(res.body.error).toContain('totally_unknown_op');
    });

    it('estimates a single known operation using the static fee schedule', async () => {
      const res = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operation: 'issue_credential' });

      expect(res.status).toBe(200);
      expect(res.body.estimates).toHaveLength(1);
      const est = res.body.estimates[0];
      expect(est.operation).toBe('issue_credential');
      expect(est.source).toBe('schedule');
      expect(est.sample_size).toBe(0);
      expect(est.confidence).toBe('low');
      expect(est.resource_fee_stroops).toBeGreaterThan(0);
      expect(est.inclusion_fee_stroops).toBe(100);
      expect(est.total_fee_stroops).toBe(est.resource_fee_stroops + 100);
      expect(est.total_fee_xlm).toBeGreaterThan(0);
      expect(est.total_fee_usd).toBeGreaterThan(0);
    });

    it('uses observed average when operations have been recorded', async () => {
      // Record 60 calls of 20,000 stroops each → avg = 20,000, high confidence
      for (let i = 0; i < 60; i++) {
        tracker.record('is_attested', '20000');
      }

      const res = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operation: 'is_attested' });

      expect(res.status).toBe(200);
      const est = res.body.estimates[0];
      expect(est.source).toBe('observed');
      expect(est.sample_size).toBe(60);
      expect(est.resource_fee_stroops).toBe(20000);
      expect(est.confidence).toBe('high');
    });

    it('returns medium confidence for 10–49 observed samples', async () => {
      for (let i = 0; i < 15; i++) {
        tracker.record('get_slice', '3000');
      }
      const res = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operation: 'get_slice' });

      expect(res.status).toBe(200);
      expect(res.body.estimates[0].confidence).toBe('medium');
    });

    it('estimates multiple operations in one request', async () => {
      const res = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operations: ['issue_credential', 'attest', 'get_credential'] });

      expect(res.status).toBe(200);
      expect(res.body.estimates).toHaveLength(3);
      expect(res.body.totals.total_fee_stroops).toBeGreaterThan(0);
      expect(res.body.totals.total_fee_xlm).toBeGreaterThan(0);
      expect(res.body.totals.total_fee_usd).toBeGreaterThan(0);
      expect(res.body.fee_schedule).toBeDefined();
    });

    it('skips unknown operations but still returns estimates for known ones', async () => {
      const res = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operations: ['issue_credential', 'unknown_op_xyz'] });

      expect(res.status).toBe(200);
      expect(res.body.estimates).toHaveLength(1);
      expect(res.body.estimates[0].operation).toBe('issue_credential');
      expect(res.body.warnings).toHaveLength(1);
      expect(res.body.warnings[0]).toContain('unknown_op_xyz');
    });

    it('accepts single-string "operation" field as well as "operations" array', async () => {
      const singleField = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operation: 'attest' });
      expect(singleField.status).toBe(200);
      expect(singleField.body.estimates[0].operation).toBe('attest');

      const arrayField = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operations: ['attest'] });
      expect(arrayField.status).toBe(200);
      expect(arrayField.body.estimates[0].operation).toBe('attest');
    });

    it('totals match the sum of individual estimates', async () => {
      const res = await request(app)
        .post('/api/costs/estimate-gas')
        .send({ operations: ['create_slice', 'add_attestor', 'get_slice'] });

      expect(res.status).toBe(200);
      const sumStroops = res.body.estimates.reduce(
        (acc: number, e: { total_fee_stroops: number }) => acc + e.total_fee_stroops,
        0,
      );
      expect(res.body.totals.total_fee_stroops).toBe(sumStroops);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. GET /api/costs/fee-schedule  (Issue #1562)
  // ---------------------------------------------------------------------------
  describe('GET /api/costs/fee-schedule', () => {
    it('returns a schedule array with all known operations', async () => {
      const res = await request(app).get('/api/costs/fee-schedule');

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.schedule)).toBe(true);
      expect(res.body.schedule.length).toBeGreaterThan(0);
      expect(res.body.xlm_usd_price).toBeDefined();
      expect(res.body.note).toBeDefined();
    });

    it('each schedule entry has the required fields', async () => {
      const res = await request(app).get('/api/costs/fee-schedule');

      expect(res.status).toBe(200);
      for (const entry of res.body.schedule) {
        expect(typeof entry.operation).toBe('string');
        expect(typeof entry.baseline_resource_fee_stroops).toBe('number');
        expect(entry.inclusion_fee_stroops).toBe(100);
        expect(entry.total_fee_stroops).toBe(
          entry.baseline_resource_fee_stroops + entry.inclusion_fee_stroops,
        );
        expect(entry.total_fee_xlm).toBeGreaterThan(0);
        expect(entry.total_fee_usd).toBeGreaterThan(0);
      }
    });

    it('includes entries for the primary Soroban operations', async () => {
      const res = await request(app).get('/api/costs/fee-schedule');

      const operations = res.body.schedule.map((e: { operation: string }) => e.operation);
      expect(operations).toContain('issue_credential');
      expect(operations).toContain('attest');
      expect(operations).toContain('create_slice');
      expect(operations).toContain('mint_sbt');
      expect(operations).toContain('verify_groth16_proof');
    });
  });
});
