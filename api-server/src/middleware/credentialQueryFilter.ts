/**
 * Credential Query Filter Middleware — Issue #1563
 *
 * Verifiers previously had to fetch all credentials and filter client-side.
 * This middleware adds server-side filtering to GET /api/credentials/search
 * and GET /api/credentials (list) by normalising the simple query params
 * callers are most likely to reach for first:
 *
 *   credential_type=PE         — shorthand alias for `type=`
 *   status=active              — active | revoked | suspended
 *   issuer=G...                — Stellar address of the issuing entity
 *   subject=G...               — Stellar address of the credential holder
 *
 * Design:
 * - `credential_type` is normalised to `type` so the upstream search handler
 *   sees a single canonical param name.
 * - All values are validated against an allowlist or format check before
 *   reaching the search layer, defending against injection via unusual inputs.
 * - Unknown/misspelled filter params that *look* like filter intents
 *   (contain "type" or "status") are flagged in a `filter_warnings` array
 *   returned in the 400 response rather than silently ignored, improving DX.
 * - The middleware is intentionally lightweight — it does no I/O and adds
 *   negligible latency.  Complex tree-based filters (`filter[and]...`) are
 *   handled downstream by `searchFilterParser.ts`.
 */

import type { Request, Response, NextFunction } from 'express';

/** Valid values for the status filter. */
const VALID_STATUSES = new Set(['active', 'revoked', 'suspended']);

/**
 * Maximum length allowed for free-form string filter values (issuer, subject,
 * credential_type).  Prevents absurdly long strings from reaching the search
 * layer.
 */
const MAX_FILTER_VALUE_LENGTH = 256;

/**
 * Validate a single filter value: must be a non-empty string within the
 * length cap containing only safe characters (alphanumeric, common
 * punctuation, Stellar address characters).
 *
 * Rejects values containing shell metacharacters, SQL injection probes, or
 * raw HTML — defence-in-depth since the search layer does not evaluate these
 * as code, but keeping the inputs clean reduces accident surface area.
 */
function isValidFilterValue(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > MAX_FILTER_VALUE_LENGTH) return false;
  // Disallow common injection probe characters.
  if (/[<>'"`;\(\)\\]/.test(value)) return false;
  return true;
}

export interface FilterValidationError {
  param: string;
  message: string;
}

/**
 * Parse and validate the simple credential filter params from `req.query`.
 * Returns either a validated filter object or an array of validation errors.
 */
export function parseCredentialFilters(query: Record<string, unknown>): {
  filters: Record<string, string | string[]>;
  errors: FilterValidationError[];
  warnings: string[];
} {
  const filters: Record<string, string | string[]> = {};
  const errors: FilterValidationError[] = [];
  const warnings: string[] = [];

  // ── credential_type → type alias ─────────────────────────────────────────
  // Support both `credential_type=PE` (intuitive) and `type=PE` (legacy).
  // If both are supplied `credential_type` wins.
  const rawCredentialType = query.credential_type ?? query.type;
  if (rawCredentialType !== undefined) {
    const values = Array.isArray(rawCredentialType) ? rawCredentialType : [rawCredentialType];
    const validated: string[] = [];
    for (const v of values) {
      if (!isValidFilterValue(v)) {
        errors.push({ param: 'credential_type', message: `Invalid value: "${v}". Must be a non-empty string up to ${MAX_FILTER_VALUE_LENGTH} characters with no special characters.` });
      } else {
        validated.push(v);
      }
    }
    if (validated.length > 0) {
      filters.type = validated.length === 1 ? validated[0] : validated;
    }
  }

  // ── status ────────────────────────────────────────────────────────────────
  if (query.status !== undefined) {
    const v = query.status;
    if (typeof v === 'string') {
      const normalized = v.toLowerCase().trim();
      if (!VALID_STATUSES.has(normalized)) {
        errors.push({
          param: 'status',
          message: `Invalid status "${v}". Must be one of: ${Array.from(VALID_STATUSES).join(', ')}.`,
        });
      } else {
        filters.status = normalized;
      }
    } else {
      errors.push({ param: 'status', message: 'status must be a single string value.' });
    }
  }

  // ── issuer ────────────────────────────────────────────────────────────────
  if (query.issuer !== undefined) {
    const values = Array.isArray(query.issuer) ? query.issuer : [query.issuer];
    const validated: string[] = [];
    for (const v of values) {
      if (!isValidFilterValue(v)) {
        errors.push({ param: 'issuer', message: `Invalid issuer value: "${v}".` });
      } else {
        validated.push(v);
      }
    }
    if (validated.length > 0) {
      filters.issuer = validated.length === 1 ? validated[0] : validated;
    }
  }

  // ── subject ───────────────────────────────────────────────────────────────
  if (query.subject !== undefined) {
    if (!isValidFilterValue(query.subject)) {
      errors.push({ param: 'subject', message: `Invalid subject value.` });
    } else {
      filters.subject = query.subject as string;
    }
  }

  // ── Warn about probable typos/misspellings ────────────────────────────────
  const knownFilterParams = new Set([
    'credential_type', 'type', 'status', 'issuer', 'subject',
    // These are handled downstream; not our concern here.
    'q', 'cursor', 'limit', 'sort_by', 'sort_order', 'facets',
    'issuer_type', 'jurisdiction',
    'attestation_count_min', 'attestation_count_max',
    'created_after', 'created_before', 'expires_after', 'expires_before',
    'filter', 'deduplicate', 'show_all', 'include_versions', 'include_score',
    'owner',
  ]);
  for (const key of Object.keys(query)) {
    if (!knownFilterParams.has(key) && (key.includes('type') || key.includes('status'))) {
      warnings.push(`Unknown parameter "${key}" — did you mean "credential_type" or "status"?`);
    }
  }

  return { filters, errors, warnings };
}

/**
 * Express middleware that validates simple credential filter params and
 * normalises `credential_type` → `type`.
 *
 * On validation errors it returns 400 with a structured error body.
 * On success it mutates `req.query` in place so downstream handlers see
 * the normalised, validated params.
 */
export function credentialQueryFilterMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const { filters, errors, warnings } = parseCredentialFilters(
    req.query as Record<string, unknown>,
  );

  if (errors.length > 0) {
    res.status(400).json({
      error: 'Invalid filter parameters',
      filter_errors: errors,
      ...(warnings.length > 0 && { filter_warnings: warnings }),
    });
    return;
  }

  // Apply normalised filters back to req.query so the route handler picks them up.
  for (const [key, value] of Object.entries(filters)) {
    (req.query as Record<string, unknown>)[key] = value;
  }

  // Remove `credential_type` after normalising to `type` so the downstream
  // handler doesn't see a redundant param.
  if ('credential_type' in req.query) {
    delete (req.query as Record<string, unknown>).credential_type;
  }

  next();
}
