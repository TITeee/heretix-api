import { normalizeVersion } from './version.js';
import { panVersionToInt } from './pan-version.js';

/** AdvisoryAffectedProduct.vendor for Palo Alto Networks rows (pan-fetcher.ts). */
export const PAN_VENDOR = 'paloalto';

/**
 * Encode a version for AdvisoryAffectedProduct's *Int columns, or for
 * comparing a queried version against them. Vendor-specific because PAN's
 * hotfix suffix ("10.2.9-h1", after 10.2.9) is the opposite of what
 * normalizeVersion() assumes a "-<letter>" suffix means (a pre-release, before
 * it) -- see pan-version.ts. Writer (advisory-fetcher.ts) and reader
 * (routes/vulnerabilities.ts) must both go through here so the stored bound
 * and the queried version are always encoded the same way.
 */
export function encodeAdvisoryVersion(vendor: string, version: string): bigint | null {
  return vendor === PAN_VENDOR ? panVersionToInt(version) : normalizeVersion(version);
}
