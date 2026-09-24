/**
 * Issue #1309 — OpenAPI 3.1 spec generator.
 *
 * `buildOpenApiSpec()` assembles the full document from the typed path
 * fragments in `./paths/*` and the shared `./components`. It is called
 * fresh on every request to `/api-docs/openapi.json` (see
 * `../routes/docs.ts`) rather than reading a static file, so the served
 * spec can never go stale relative to what's in source control — and the
 * same function is what `scripts/generate-openapi-spec.ts` calls to write
 * the on-disk snapshot consumed by the TypeScript client generator.
 *
 * Only routers that are actually mounted in `index.ts` are represented
 * here. A handful of route modules exist in the codebase but are not
 * wired into the running app (only exercised directly by their unit
 * tests) — documenting those would describe endpoints that 404 in
 * practice, so they're intentionally excluded.
 */

import type { OpenAPIObject, PathItemObject } from 'openapi3-ts/oas31';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { components, tags } from './components.js';
import type { PathsFragment } from './paths/types.js';

import { healthPaths } from './paths/health.js';
import { verifyPaths } from './paths/verify.js';
import { slicesPaths } from './paths/slices.js';
import { sbtPaths } from './paths/sbt.js'; // #1564 SBT reverse index
import { apiKeysPaths } from './paths/apiKeys.js';
import { webhooksPaths } from './paths/webhooks.js';
import { gdprPaths } from './paths/gdpr.js';
import { oauth2Paths } from './paths/oauth2.js';
import { attestorsPaths } from './paths/attestors.js';
import { notificationsPaths } from './paths/notifications.js';
import { issuerPaths } from './paths/issuer.js';
import { analyticsPaths } from './paths/analytics.js';
import { issuerAnalyticsPaths } from './paths/issuerAnalytics.js';
import { dashboardPaths } from './paths/dashboard.js';
import { credentialsPaths } from './paths/credentials.js';
import { credentialExportPaths } from './paths/credentialExport.js';
import { consentPaths } from './paths/consent.js';
import { shareLinksPaths } from './paths/shareLinks.js';
import { recoveryPaths } from './paths/recovery.js';
import { privilegeEscalationPaths } from './paths/privilegeEscalation.js';
import { tracingPaths } from './paths/tracing.js';
import { metricsPaths } from './paths/metrics.js';
import { costsPaths } from './paths/costs.js';
import { bridgePaths } from './paths/bridge.js';
import { auditPaths } from './paths/audit.js';
import { authAuditPaths } from './paths/authAudit.js';
import { graphqlPaths } from './paths/graphql.js';
import { passwordlessAuthPaths } from './paths/passwordlessAuth.js';
import { reportsPaths } from './paths/reports.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf-8')) as { version: string };

/** Re-mounts every operation in `fragment` under `newPrefix` instead of `oldPrefix`. */
function remount(fragment: PathsFragment, oldPrefix: string, newPrefix: string): PathsFragment {
  const out: PathsFragment = {};
  for (const [path, item] of Object.entries(fragment)) {
    if (!path.startsWith(oldPrefix)) {
      throw new Error(`remount: path "${path}" does not start with "${oldPrefix}"`);
    }
    out[newPrefix + path.slice(oldPrefix.length)] = item;
  }
  return out;
}

function mergePaths(...fragments: PathsFragment[]): Record<string, PathItemObject> {
  const merged: Record<string, PathItemObject> = {};
  for (const fragment of fragments) {
    for (const [path, item] of Object.entries(fragment)) {
      if (merged[path]) {
        throw new Error(`buildOpenApiSpec: duplicate path definition for "${path}"`);
      }
      merged[path] = item;
    }
  }
  return merged;
}

export function buildOpenApiSpec(): OpenAPIObject {
  const paths = mergePaths(
    healthPaths,
    verifyPaths,
    slicesPaths,
    sbtPaths, // #1564 SBT reverse index
    apiKeysPaths,
    // apiKeysRouter is mounted twice in index.ts: /api/api-keys (legacy)
    // and /auth/api-keys (issue #1297's spec-mandated path). Same handlers,
    // same behaviour — re-derive the second path set instead of hand
    // duplicating every operation object.
    remount(apiKeysPaths, '/api/api-keys', '/auth/api-keys'),
    webhooksPaths,
    gdprPaths,
    oauth2Paths,
    attestorsPaths,
    notificationsPaths,
    issuerPaths,
    analyticsPaths,
    issuerAnalyticsPaths,
    dashboardPaths,
    credentialsPaths,
    credentialExportPaths,
    consentPaths,
    shareLinksPaths,
    recoveryPaths,
    privilegeEscalationPaths,
    tracingPaths,
    metricsPaths,
    costsPaths,
    bridgePaths,
    auditPaths,
    authAuditPaths,
    graphqlPaths,
    passwordlessAuthPaths,
    reportsPaths,
  );

  const baseUrl = (process.env.PUBLIC_APP_BASE_URL ?? 'http://localhost:3000').replace(/\/+$/, '');

  return {
    openapi: '3.1.0',
    info: {
      title: 'QuorumProof API',
      version: pkg.version,
      description:
        'REST API for the QuorumProof credential issuance, attestation and verification ' +
        'platform, backed by Soroban smart contracts on Stellar.\n\n' +
        'This document is generated from typed operation definitions in ' +
        '`api-server/src/openapi/paths/*` — see `docs/API_DOCUMENTATION.md` for how to ' +
        'regenerate it and the TypeScript client after changing a route.',
      contact: { name: 'QuorumProof', url: 'https://github.com/QuorumProof/QuorumProof' },
    },
    servers: [
      { url: baseUrl, description: 'Configured server (PUBLIC_APP_BASE_URL)' },
      { url: 'http://localhost:3000', description: 'Local development' },
    ],
    tags,
    paths,
    components,
  };
}
