import type { PathsFragment } from './types.js';

/**
 * OpenAPI path definitions for gas cost reporting and estimation endpoints.
 * Issue #4 (existing reporting) + Issue #1562 (new estimation endpoint).
 */
export const costsPaths: PathsFragment = {
  '/api/costs/report': {
    get: {
      tags: ['Costs'],
      summary: 'Aggregated gas cost report',
      description: 'Returns aggregated gas cost data across all tracked on-chain operations.',
      responses: {
        '200': {
          description: 'Gas cost report.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                additionalProperties: true,
              },
            },
          },
        },
      },
    },
  },
  '/api/costs/optimizations': {
    get: {
      tags: ['Costs'],
      summary: 'Ranked optimisation recommendations',
      description: 'Returns a ranked list of operations worth optimising, ordered by estimated savings.',
      parameters: [
        {
          name: 'top',
          in: 'query',
          description: 'Number of top recommendations to return (default 5).',
          schema: { type: 'integer', minimum: 1, default: 5 },
        },
      ],
      responses: {
        '200': {
          description: 'Optimisation recommendations.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  recommendations: { type: 'array', items: { type: 'object', additionalProperties: true } },
                },
              },
            },
          },
        },
      },
    },
  },
  '/api/costs/projection': {
    get: {
      tags: ['Costs'],
      summary: 'Project future gas costs for an operation',
      description: 'Estimates future gas costs for a given operation based on call frequency and duration.',
      parameters: [
        { name: 'operation', in: 'query', required: true, schema: { type: 'string' }, description: 'Operation name to project.' },
        { name: 'callsPerDay', in: 'query', required: true, schema: { type: 'number' }, description: 'Estimated calls per day.' },
        { name: 'days', in: 'query', schema: { type: 'number', default: 30 }, description: 'Projection horizon in days (default 30).' },
      ],
      responses: {
        '200': {
          description: 'Cost projection result.',
          content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } },
        },
        '400': {
          description: 'Missing or invalid parameters.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
        },
        '404': {
          description: 'No recorded cost data for the given operation.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
        },
      },
    },
  },
  '/api/costs/estimate-gas': {
    post: {
      tags: ['Costs'],
      summary: 'Estimate gas cost for one or more operations',
      description:
        'Returns a per-operation gas cost estimate before a transaction is submitted, ' +
        'improving UX by letting callers show "this will cost ~X XLM" warnings. ' +
        'Uses observed averages from the gas cost tracker when available; falls back ' +
        'to a static fee schedule for operations with no recorded data (Issue #1562).\n\n' +
        'Pass either `"operation": "op_name"` for a single operation, or ' +
        '`"operations": ["op1", "op2"]` for a batch (max 20).',
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                operation: {
                  type: 'string',
                  description: 'Single operation name.',
                  example: 'issue_credential',
                },
                operations: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Multiple operation names (max 20).',
                  example: ['issue_credential', 'attest'],
                },
              },
            },
          },
        },
      },
      responses: {
        '200': {
          description: 'Gas estimates per operation plus aggregate totals.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  estimates: {
                    type: 'array',
                    items: {
                      type: 'object',
                      properties: {
                        operation: { type: 'string' },
                        source: { type: 'string', enum: ['observed', 'schedule'], description: 'Data source for this estimate.' },
                        sample_size: { type: 'integer', description: 'Number of observed calls (0 for schedule-only).' },
                        resource_fee_stroops: { type: 'integer' },
                        inclusion_fee_stroops: { type: 'integer' },
                        total_fee_stroops: { type: 'integer' },
                        total_fee_xlm: { type: 'number' },
                        total_fee_usd: { type: 'number' },
                        xlm_usd_price: { type: 'number' },
                        confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
                      },
                    },
                  },
                  totals: {
                    type: 'object',
                    properties: {
                      total_fee_stroops: { type: 'integer' },
                      total_fee_xlm: { type: 'number' },
                      total_fee_usd: { type: 'number' },
                    },
                  },
                  fee_schedule: { type: 'object', additionalProperties: { type: 'integer' }, description: 'Full static fee schedule for reference.' },
                  warnings: { type: 'array', items: { type: 'string' }, description: 'Warnings for unknown operations that were skipped.' },
                },
              },
            },
          },
        },
        '400': {
          description: 'Missing, invalid, or too many operations in the request body.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
        },
        '422': {
          description: 'All requested operations are unknown (not in the fee schedule and no observed data).',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
        },
      },
    },
  },
  '/api/costs/fee-schedule': {
    get: {
      tags: ['Costs'],
      summary: 'Static fee schedule for all known operations',
      description:
        'Returns the full static fee schedule — baseline stroop estimates per operation ' +
        'derived from Soroban testnet simulations. Overridable via GAS_FEE_* env vars. ' +
        'Prefer POST /api/costs/estimate-gas for observed averages (Issue #1562).',
      responses: {
        '200': {
          description: 'Fee schedule with per-operation cost breakdown.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  schedule: {
                    type: 'array',
                    items: {
                      type: 'object',
                      properties: {
                        operation: { type: 'string' },
                        baseline_resource_fee_stroops: { type: 'integer' },
                        inclusion_fee_stroops: { type: 'integer' },
                        total_fee_stroops: { type: 'integer' },
                        total_fee_xlm: { type: 'number' },
                        total_fee_usd: { type: 'number' },
                      },
                    },
                  },
                  xlm_usd_price: { type: 'number' },
                  note: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  },
};
