import { normalizeVersion } from './version.js';
import { panVersionToInt } from './pan-version.js';
import { ivantiVersionToInt } from './ivanti-version.js';
import { citrixVersionToInt } from './citrix-version.js';
import { microsoftVersionToInt } from './microsoft-version.js';
import { sonicWallVersionToInt } from './sonicwall-version.js';
import { broadcomVersionToInt } from './broadcom-version.js';

/** AdvisoryAffectedProduct.vendor for Palo Alto Networks rows (pan-fetcher.ts). */
export const PAN_VENDOR = 'paloalto';
/** AdvisoryAffectedProduct.vendor for Ivanti rows (ivanti-fetcher.ts). */
export const IVANTI_VENDOR = 'ivanti';
/** AdvisoryAffectedProduct.vendor for NetScaler (Citrix ADC / Gateway) rows (citrix-fetcher.ts). */
export const CITRIX_VENDOR = 'citrix';
/** AdvisoryAffectedProduct.vendor for Windows Server rows (msrc-fetcher.ts). */
export const MICROSOFT_VENDOR = 'microsoft';
/** AdvisoryAffectedProduct.vendor for SonicWall rows (sonicwall-fetcher.ts). */
export const SONICWALL_VENDOR = 'sonicwall';
/** AdvisoryAffectedProduct.vendor for VMware rows (broadcom-fetcher.ts). */
export const BROADCOM_VENDOR = 'broadcom';

/**
 * Vendors whose rows are encoded with their own version order instead of
 * normalizeVersion(). A search has to encode the queried version once per
 * entry here and compare it only against that vendor's rows.
 */
const VENDOR_VERSION_ENCODERS: Record<string, (version: string) => bigint | null> = {
  [PAN_VENDOR]: panVersionToInt,
  [IVANTI_VENDOR]: ivantiVersionToInt,
  [CITRIX_VENDOR]: citrixVersionToInt,
  [MICROSOFT_VENDOR]: microsoftVersionToInt,
  [SONICWALL_VENDOR]: sonicWallVersionToInt,
  [BROADCOM_VENDOR]: broadcomVersionToInt,
};

export const VENDORS_WITH_OWN_VERSION_ORDER = Object.keys(VENDOR_VERSION_ENCODERS);

/**
 * The AdvisoryVulnerability.source each vendor above is imported under (its fetcher's
 * source()). A search result carries only the source, so choosing between two fixes from
 * one advisory feed goes through here to order them the vendor's way.
 */
export const OWN_VERSION_ORDER_SOURCES: Record<string, string> = {
  [PAN_VENDOR]: 'paloalto',
  [IVANTI_VENDOR]: 'advisory-ivanti',
  [CITRIX_VENDOR]: 'advisory-citrix',
  [MICROSOFT_VENDOR]: 'advisory-microsoft',
  [SONICWALL_VENDOR]: 'advisory-sonicwall',
  [BROADCOM_VENDOR]: 'advisory-broadcom',
};

/**
 * Encode a version for AdvisoryAffectedProduct's *Int columns, or for
 * comparing a queried version against them. Vendor-specific where
 * normalizeVersion() misorders the vendor's versions: PAN's hotfix suffix
 * ("10.2.9-h1", after 10.2.9) is the opposite of what normalizeVersion()
 * assumes a "-<letter>" suffix means (a pre-release, before it) -- see
 * pan-version.ts -- and Ivanti's fix boundaries sit in a 4th numeric component
 * that normalizeVersion() drops -- see ivanti-version.ts -- and NetScaler's
 * branch-plus-build versions ("14.1-73.32"), of which normalizeVersion() keeps only
 * the 73 -- see citrix-version.ts -- and Windows builds ("10.0.20348.5761"),
 * whose build normalizeVersion() capped and whose update revision it dropped
 * until 2026-11 -- see microsoft-version.ts -- and SonicWall's release-plus-build
 * versions ("7.0.1-R1456"), whose letter-led build normalizeVersion() reads as a
 * pre-release -- see sonicwall-version.ts -- and VMware's updates, of which
 * normalizeVersion() reads only the "8.0 U3e" spelling ("6.7u2c" became 6.72 and
 * ESXi image names nothing) -- see broadcom-version.ts. Writer
 * (advisory-fetcher.ts) and reader (routes/vulnerabilities.ts) must both go
 * through here so the stored bound and the queried version are always encoded
 * the same way.
 */
export function encodeAdvisoryVersion(vendor: string, version: string): bigint | null {
  const encode = VENDOR_VERSION_ENCODERS[vendor];
  return encode ? encode(version) : normalizeVersion(version);
}
