import type { PathsFragment } from './types.js';

export const credentialsPaths: PathsFragment = {
  '/api/credentials/search': {
    get: {
      tags: ['Credentials'],
      summary: 'Advanced credential search',
      description:
        'Full-text search, faceting, ranking, deduplication and cursor-based pagination. ' +
        'Also supports per-field operators (`attestation_count[gte]=2`, `issuer[regex]=BANK.*`) ' +
        'and nested boolean combinations via `filter[and]`/`filter[or]`/`filter[not]`.',
      parameters: [
        { name: 'q', in: 'query', schema: { type: 'string' }, description: 'Full-text search query.' },
        {
          name: 'credential_type',
          in: 'query',
          schema: { type: 'array', items: { type: 'string' } },
          style: 'form',
          explode: true,
          description:
            'Filter by credential type name or numeric ID (e.g. `PE`, `1`). ' +
            'Alias for `type`; validated and normalised by the credential query filter ' +
            'middleware before reaching the search layer (Issue #1563). Repeatable.',
        },
        { name: 'type', in: 'query', schema: { type: 'array', items: { type: 'integer' } }, style: 'form', explode: true, description: 'Credential type (numeric); repeatable. Prefer `credential_type` for new integrations.' },
        { name: 'issuer', in: 'query', schema: { type: 'array', items: { type: 'string' } }, style: 'form', explode: true },
        { name: 'issuer_type', in: 'query', schema: { type: 'array', items: { type: 'string' } }, style: 'form', explode: true },
        { name: 'subject', in: 'query', schema: { type: 'string' } },
        { name: 'status', in: 'query', schema: { type: 'string', enum: ['active', 'revoked', 'suspended'] } },
        { name: 'jurisdiction', in: 'query', schema: { type: 'array', items: { type: 'string' } }, style: 'form', explode: true, description: 'ISO 3166 or supranational code; hierarchical (US matches US-CA, EU matches EU members).' },
        { name: 'attestation_count_min', in: 'query', schema: { type: 'integer' } },
        { name: 'attestation_count_max', in: 'query', schema: { type: 'integer' } },
        { name: 'created_after', in: 'query', schema: { type: 'string', format: 'date-time' } },
        { name: 'created_before', in: 'query', schema: { type: 'string', format: 'date-time' } },
        { name: 'expires_after', in: 'query', schema: { type: 'string', format: 'date-time' } },
        { name: 'expires_before', in: 'query', schema: { type: 'string', format: 'date-time' } },
        { name: 'deduplicate', in: 'query', schema: { type: 'boolean' }, description: 'Collapse same subject+issuer credentials to the highest version.' },
        { name: 'include_versions', in: 'query', schema: { type: 'boolean' } },
        { name: 'include_score', in: 'query', schema: { type: 'boolean' } },
        { name: 'cursor', in: 'query', schema: { type: 'string' } },
        { name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 } },
        { name: 'sort_by', in: 'query', schema: { type: 'string' }, description: 'Comma-separated: id|type|relevance|created_at|updated_at|recency|reputation.' },
        { name: 'sort_order', in: 'query', schema: { type: 'string', enum: ['asc', 'desc'] } },
        { name: 'facets', in: 'query', schema: { type: 'string' }, description: 'Comma-separated facet names.' },
      ],
      responses: {
        '200': {
          description: 'Search results with facets and pagination.',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  data: { type: 'array', items: { $ref: '#/components/schemas/Credential' } },
                  facets: { type: 'object', additionalProperties: true },
                  pagination: { $ref: '#/components/schemas/Pagination' },
                  query_info: { type: 'object', additionalProperties: true },
                  index_version: { type: 'integer' },
                },
              },
            },
          },
        },
        '400': { description: 'Invalid limit, sort_by, sort_order, or filter parameter (e.g. invalid status value — see Issue #1563 filter middleware).', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
  '/api/credentials/search/rebuild-index-async': {
    post: {
      tags: ['Credentials'],
      summary: 'Kick off a background full re-index from chain',
      description: 'The current index stays live and queryable for the whole rebuild; swapped in atomically on completion.',
      responses: {
        '202': { description: 'Rebuild started.', content: { 'application/json': { schema: { type: 'object', properties: { rebuild_id: { type: 'string' }, status: { type: 'string' }, estimated_duration_ms: { type: 'number' } } } } } },
        '409': { description: 'A rebuild is already in progress.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
  '/api/credentials/search/rebuild-status/{id}': {
    get: {
      tags: ['Credentials'],
      summary: 'Get the status of a background re-index job',
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
      responses: {
        '200': { description: 'Job status.', content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } },
        '404': { description: 'Not found.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
  '/api/credentials/search/rebuild-history': {
    get: {
      tags: ['Credentials'],
      summary: 'List past re-index jobs',
      responses: { '200': { description: 'Rebuild history.', content: { 'application/json': { schema: { type: 'object', properties: { rebuilds: { type: 'array', items: { type: 'object', additionalProperties: true } } } } } } } },
    },
  },
  '/api/credentials/verify-batch': {
    post: {
      tags: ['Credentials'],
      summary: 'Batch-check attestation status against a slice',
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                credential_ids: { type: 'array', items: { type: 'integer', minimum: 1 }, minItems: 1, maxItems: 50 },
                slice_id: { type: 'integer', minimum: 1 },
              },
              required: ['credential_ids', 'slice_id'],
            },
          },
        },
      },
      responses: {
        '200': {
          description: 'Per-credential attestation results.',
          content: {
            'application/json': {
              schema: { type: 'object', properties: { results: { type: 'array', items: { type: 'object', properties: { credential_id: { type: 'integer' }, attested: { type: 'boolean' }, error: { type: ['string', 'null'] } } } } } },
            },
          },
        },
        '400': { description: 'Invalid credential_ids or slice_id.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
  '/api/credentials/search/refresh-index': {
    post: {
      tags: ['Credentials'],
      summary: 'Force a synchronous refresh of the search index from chain',
      responses: {
        '200': { description: 'Refreshed.', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, index_size: { type: 'integer' }, cache_size: { type: 'integer' }, last_indexed: { type: ['string', 'null'], format: 'date-time' } } } } } },
      },
    },
  },
  '/api/credentials/search/index-stats': {
    get: {
      tags: ['Credentials'],
      summary: 'Get search index and metadata-hash cache statistics',
      responses: { '200': { description: 'Stats.', content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } } },
    },
  },
  '/api/credentials/crl': {
    get: {
      tags: ['Credentials'],
      summary: 'Export the revocation list (CRL)',
      description: 'X.509-compatible JSON structure; `format=pem` wraps it as base64 in a PEM envelope.',
      parameters: [
        { name: 'issuer', in: 'query', schema: { type: 'string', default: 'QuorumProof' } },
        { name: 'format', in: 'query', schema: { type: 'string', enum: ['json', 'pem'], default: 'json' } },
      ],
      responses: {
        '200': {
          description: 'The CRL.',
          content: {
            'application/json': { schema: { type: 'object', properties: { version: { type: 'integer' }, issuer: { type: 'string' }, thisUpdate: { type: 'string', format: 'date-time' }, nextUpdate: { type: 'string', format: 'date-time' }, revokedCertificates: { type: 'array', items: { type: 'object', additionalProperties: true } }, totalRevoked: { type: 'integer' } } } },
            'text/plain': { schema: { type: 'string', description: 'PEM-encoded CRL when format=pem.' } },
          },
        },
        '400': { description: 'Invalid format.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
  '/api/credentials/shards/stats': {
    get: {
      tags: ['Credentials'],
      summary: 'Get sharded-storage distribution statistics',
      responses: { '200': { description: 'Shard stats.', content: { 'application/json': { schema: { type: 'object', properties: { shard_count: { type: 'integer' }, total_credentials: { type: 'integer' }, shards: { type: 'array', items: { type: 'object', additionalProperties: true } } } } } } } },
    },
  },
  '/api/credentials/shards/by-subject': {
    get: {
      tags: ['Credentials'],
      summary: "Fetch a subject's credentials directly from its shard",
      parameters: [{ name: 'subject', in: 'query', required: true, schema: { type: 'string' } }],
      responses: {
        '200': { description: 'Credentials in the subject shard.', content: { 'application/json': { schema: { type: 'object', properties: { subject: { type: 'string' }, shard_index: { type: 'integer' }, count: { type: 'integer' }, credentials: { type: 'array', items: { $ref: '#/components/schemas/Credential' } } } } } } },
        '400': { description: 'Missing subject.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
  '/api/credentials/{id}/metadata-hash': {
    get: {
      tags: ['Credentials'],
      summary: 'Get the metadata hash for a credential (cached)',
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer', minimum: 1 } }],
      responses: {
        '200': { description: 'Metadata hash.', content: { 'application/json': { schema: { type: 'object', properties: { credential_id: { type: 'integer' }, metadata_hash: { type: 'string' }, cached: { type: 'boolean' } } } } } },
        '400': { description: 'Invalid credential id.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
        '404': { description: 'Credential not found.', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } } },
      },
    },
  },
};
