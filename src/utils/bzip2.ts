import { createRequire } from 'module';

// seek-bzip is CommonJS with no type definitions.
const require = createRequire(import.meta.url);
const seekBzip = require('seek-bzip') as {
  decode(input: Buffer, output?: Buffer | number, multistream?: boolean): Buffer;
};

/**
 * Decompress a bzip2 file held in memory.
 *
 * Used for the Red Hat and Oracle Linux OVAL feeds. Every block's CRC and the
 * stream CRC are checked, so a corrupt result throws instead of being returned.
 * The previous decoder (the `bzip2` package) silently garbled the output from
 * the second 900 KB block on for some files, which dropped or mangled OVAL
 * definitions without an error. Concatenated streams (as written by parallel
 * compressors) are decoded too.
 */
export function decompressBzip2(data: Uint8Array): Buffer {
  return seekBzip.decode(Buffer.from(data.buffer, data.byteOffset, data.byteLength), undefined, true);
}
