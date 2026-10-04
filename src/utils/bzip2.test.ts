import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { decompressBzip2 } from './bzip2.js';

// The first 950,000 bytes of Red Hat's RHEL 8 OVAL feed (Red Hat security
// data, CC BY 4.0), recompressed with `bzip2 -9`. Two blocks: the previous
// decoder garbled everything from the second block on for this file.
const FIXTURE = fileURLToPath(new URL('./__fixtures__/rhel-8-oval-head.xml.bz2', import.meta.url));
const EXPECTED_LENGTH = 950_000;
const EXPECTED_SHA256 = '780912937f8855114cbade5b3dc574c842581ae6a5291a271be5337ebbbdad6a';

describe('decompressBzip2', () => {
  it('decodes a multi-block file exactly', () => {
    const out = decompressBzip2(readFileSync(FIXTURE));
    expect(out.length).toBe(EXPECTED_LENGTH);
    expect(createHash('sha256').update(out).digest('hex')).toBe(EXPECTED_SHA256);
    expect(out.subarray(0, 20).toString()).toBe('<?xml version="1.0" ');
  });

  it('decodes concatenated streams', () => {
    const one = readFileSync(FIXTURE);
    const out = decompressBzip2(Buffer.concat([one, one]));
    expect(out.length).toBe(EXPECTED_LENGTH * 2);
  });

  it('throws on corrupt input instead of returning garbled data', () => {
    const corrupt = Buffer.from(readFileSync(FIXTURE));
    corrupt[corrupt.length >> 1] ^= 0xff;
    expect(() => decompressBzip2(corrupt)).toThrow();
  });
});
