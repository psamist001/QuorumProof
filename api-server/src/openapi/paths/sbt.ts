import type { PathsFragment } from './types.js';

/**
 * OpenAPI path definitions for the SBT reverse index endpoints (Issue #1564).
 */
export const sbtPaths: PathsFragment = {
  '/api/sbt/holder/{address}': {
    get: {
      tags: ['SBT'],
      summary: 'List SBT IDs held by an address',
      description:
        'Returns all Soulbound Token IDs owned by the given Stellar address. ' +
        'Results are served from the server-side reverse index when fresh; ' +
        'otherwise the authoritative on-chain `get_tokens_by_holder` function is ' +
        'called and the result is cached. The `X-Index-Source` response header ' +
        'indicates whether the result came from `cache` or `chain` (Issue #1564).',
      parameters: [
        {
          name: 'address',
          in: 'path',
          required: true,
          description: 'Stellar public key (G... format).',
          schema: { type: 'string', pattern: '^G[A-Z2-7]{55}$' },
        },
      ],
      responses: {
        '200': {
          description: 'List of SBT IDs for the holder.',
          headers: {
            'X-Index-Source': {
              description: 'Whether the result came from the local cache or the chain.',
              schema: { type: 'string', enum: ['cache', 'chain'] },
            },
          },
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  holder: { type: 'string', description: 'The queried Stellar address.' },
                  sbt_ids: {
                    type: 'array',
                    items: { type: 'integer' },
                    description: 'SBT token IDs owned by this holder.',
                  },
                  count: { type: 'integer', description: 'Total number of SBTs owned.' },
                },
              },
            },
          },
        },
        '400': {
          description: 'Invalid Stellar address.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
        },
        '500': {
          description: 'Failed to fetch index from chain.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
        },
      },
    },
  },
  '/api/sbt/holder/{address}/check': {
    get: {
      tags: ['SBT'],
      summary: 'Consistency check — local index vs chain',
      description:
        'Fetches the authoritative SBT list from the chain and compares it against the ' +
        'local reverse index. Returns a report identifying IDs that are missing from ' +
        'or spuriously present in the local cache (Issue #1564).',
      parameters: [
        {
          name: 'address',
          in: 'path',
          required: true,
          description: 'Stellar public key (G... format).',
          schema: { type: 'string', pattern: '^G[A-Z2-7]{55}$' },
        },
      ],
      responses: {
        '200': {
          description: 'Consistency report.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  holder: { type: 'string' },
                  localIds: { type: 'array', items: { type: 'integer' } },
                  chainIds: { type: 'array', items: { type: 'integer' } },
                  missingFromLocal: {
                    type: 'array',
                    items: { type: 'integer' },
                    description: 'IDs present on chain but absent from local cache.',
                  },
                  extraInLocal: {
                    type: 'array',
                    items: { type: 'integer' },
                    description: 'IDs present in local cache but absent on chain.',
                  },
                  isConsistent: { type: 'boolean' },
                },
              },
            },
          },
        },
        '400': {
          description: 'Invalid Stellar address.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
        },
      },
    },
  },
  '/api/sbt/index/migrate': {
    post: {
      tags: ['SBT'],
      summary: 'Pre-warm the local SBT reverse index',
      description:
        'Walks every existing SBT on-chain and rebuilds the server-side ' +
        'holder → SBT-IDs reverse index from scratch. Run once after initial ' +
        'deployment or after extended downtime (Issue #1564).',
      responses: {
        '200': {
          description: 'Migration completed.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  success: { type: 'boolean' },
                  holdersProcessed: { type: 'integer' },
                  sbtsIndexed: { type: 'integer' },
                  errors: { type: 'array', items: { type: 'string' } },
                },
              },
            },
          },
        },
        '500': {
          description: 'Migration failed.',
          content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
        },
      },
    },
  },
  '/api/sbt/index/stats': {
    get: {
      tags: ['SBT'],
      summary: 'Local reverse index statistics',
      description: 'Returns the number of holders and total SBT IDs currently held in the local reverse index (Issue #1564).',
      responses: {
        '200': {
          description: 'Index statistics.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  holders: { type: 'integer', description: 'Number of distinct holders in the local index.' },
                  total_indexed_sbts: { type: 'integer', description: 'Total SBT IDs across all holders.' },
                },
              },
            },
          },
        },
      },
    },
  },
};
