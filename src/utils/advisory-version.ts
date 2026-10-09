import { normalizeVersion } from './version.js';
import { panVersionToInt } from './pan-version.js';
import { ivantiVersionToInt } from './ivanti-version.js';
import { citrixVersionToInt } from './citrix-version.js';

/** AdvisoryAffectedProduct.vendor for Palo Alto Networks rows (pan-fetcher.ts). */
export const PAN_VENDOR = 'paloalto';
/** AdvisoryAffectedProduct.vendor for Ivanti rows (ivanti-fetcher.ts). */
export const IVANTI_VENDOR = 'ivanti';
/** AdvisoryAffectedProduct.vendor for NetScaler (Citrix ADC / Gateway) rows (citrix-fetcher.ts). */
export const CITRIX_VENDOR = 'citrix';

/**
 * Vendors whose rows are encoded with their own version order instead of
 * normalizeVersion(). A search has to encode the queried version once per
 * entry here and compare it only against that vendor's rows.
 */
const VENDOR_VERSION_ENCODERS: Record<string, (version: string) => bigint | null> = {
  [PAN_VENDOR]: panVersionToInt,
  [IVANTI_VENDOR]: ivantiVersionToInt,
  [CITRIX_VENDOR]: citrixVersionToInt,
};

export const VENDORS_WITH_OWN_VERSION_ORDER = Object.keys(VENDOR_VERSION_ENCODERS);

/**
 * Encode a version for AdvisoryAffectedProduct's *Int columns, or for
 * comparing a queried version against them. Vendor-specific where
 * normalizeVersion() misorders the vendor's versions: PAN's hotfix suffix
 * ("10.2.9-h1", after 10.2.9) is the opposite of what normalizeVersion()
 * assumes a "-<letter>" suffix means (a pre-release, before it) -- see
 * pan-version.ts -- and Ivanti's fix boundaries sit in a 4th numeric component
 * that normalizeVersion() drops -- see ivanti-version.ts -- and NetScaler's
 * branch-plus-build versions ("14.1-73.32"), of which normalizeVersion() keeps only
 * the 73 -- see citrix-version.ts. Writer
 * (advisory-fetcher.ts) and reader (routes/vulnerabilities.ts) must both go
 * through here so the stored bound and the queried version are always encoded
 * the same way.
 */
export function encodeAdvisoryVersion(vendor: string, version: string): bigint | null {
  const encode = VENDOR_VERSION_ENCODERS[vendor];
  return encode ? encode(version) : normalizeVersion(version);
}
