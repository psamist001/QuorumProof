import type { PathsFragment } from './types.js';

export const slicesPaths: PathsFragment = {
  '/api/slices': {
    get: {
      tags: ['Slices'],
      summary: 'List quorum slices (cursor-paginated)',
      description:
        'Returns a cursor-paginated list of quorum slices. Results for individual slices ' +
        'are served from the slice verification cache (Issue #1565). Pass `bypass_cache=1` to ' +
        'force a fresh read from the Soroban RPC layer.',
      parameters: [
        { name: 'cursor', in: 'query', schema: { type: 'string' }, description: 'Opaque base64 cursor from a previous response.' },
        { name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 } },
        { name: 'bypass_cache', in: 'query', schema: { type: 'string', enum: ['0', '1'] }, description: 'Set to 1 to skip the cache and read directly from the RPC layer.' },
      ],
      responses: {
        '200': {
          description: 'Paginated list of slices.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  data: { type: 'array', items: { $ref: '#/components/schemas/Slice' } },
                  pagination: { $ref: '#/components/schemas/Pagination' },
                },
              },
            },
          },
        },
        '400': { description: 'Invalid cursor.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
  '/api/slices/{id}': {
    get: {
      tags: ['Slices'],
      summary: 'Get a quorum slice by id',
      description:
        'Returns a single quorum slice. The response is served from the in-process ' +
        'slice verification cache (Issue #1565) when available; the `X-Cache` response ' +
        'header reports `HIT` or `MISS` accordingly.',
      parameters: [
        { name: 'id', in: 'path', required: true, schema: { type: 'integer', minimum: 1 } },
        { name: 'bypass_cache', in: 'query', schema: { type: 'string', enum: ['0', '1'] }, description: 'Set to 1 to bypass the cache.' },
      ],
      responses: {
        '200': {
          description: 'The slice.',
          headers: {
            'X-Cache': {
              description: 'Whether the response was served from cache (HIT) or fetched fresh (MISS).',
              schema: { type: 'string', enum: ['HIT', 'MISS'] },
            },
          },
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Slice' } } },
        },
        '404': { description: 'Slice not found.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
  '/api/slices/{id}/invalidate-cache': {
    post: {
      tags: ['Slices'],
      summary: 'Invalidate the cache entry for a slice',
      description:
        'Immediately removes the cached result for the given slice ID from the ' +
        'in-process slice verification cache. Use after administrative contract writes ' +
        'that bypass the normal API write path (Issue #1565).',
      parameters: [
        { name: 'id', in: 'path', required: true, schema: { type: 'integer', minimum: 1 } },
      ],
      responses: {
        '200': {
          description: 'Cache entry invalidated.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  invalidated: { type: 'boolean' },
                  sliceId: { type: 'integer' },
                },
              },
            },
          },
        },
        '400': { description: 'Invalid slice ID.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
  '/api/slices/cache/metrics': {
    get: {
      tags: ['Slices'],
      summary: 'Slice verification cache metrics',
      description:
        'Returns performance metrics for the in-process slice verification cache: ' +
        'hits, misses, invalidations, evictions, current size, and configuration (Issue #1565).',
      responses: {
        '200': {
          description: 'Cache metrics snapshot.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  hits: { type: 'integer', description: 'Number of cache hits.' },
                  misses: { type: 'integer', description: 'Number of cache misses (including TTL-expired entries).' },
                  invalidations: { type: 'integer', description: 'Number of explicit invalidations.' },
                  evictions: { type: 'integer', description: 'Number of LRU evictions due to max size.' },
                  size: { type: 'integer', description: 'Current number of entries in the cache.' },
                  maxSize: { type: 'integer', description: 'Maximum configured entries.' },
                  ttlMs: { type: 'integer', description: 'Configured TTL in milliseconds.' },
                },
              },
            },
          },
        },
      },
    },
  },
};
