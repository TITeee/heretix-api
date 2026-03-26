/**
 * CPE (Common Platform Enumeration) 2.3 parse utility
 * Format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
 *   part: a=application, o=os, h=hardware
 */
export interface ParsedCPE {
  part: string;           // "a", "o", "h"
  vendor: string;
  product: string;
  version: string | null; // null if "*" or "-"
}

/**
 * Parse a CPE 2.3 string and return a structured object.
 * Returns null for invalid formats.
 */
export function parseCPE(cpe: string): ParsedCPE | null {
  if (!cpe.startsWith('cpe:2.3:')) return null;

  const parts = cpe.split(':');
  // ["cpe", "2.3", <part>, <vendor>, <product>, <version>, ...]
  if (parts.length < 5) return null;

  const part = parts[2];
  const vendor = parts[3];
  const product = parts[4];
  const rawVersion = parts[5] ?? '*';

  if (!vendor || vendor === '*' || vendor === '-') return null;
  if (!product || product === '*' || product === '-') return null;

  const version = (rawVersion === '*' || rawVersion === '-' || rawVersion === '') ? null : rawVersion;

  return { part, vendor, product, version };
}
