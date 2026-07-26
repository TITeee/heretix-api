/**
 * Debian OSV search accuracy validation script.
 * See src/scripts/lib/osv-distro-sweep.ts for the shared sweep methodology.
 *
 * Usage:
 *   pnpm validate:debian
 */
import { runOsvDistroSweep } from './lib/osv-distro-sweep.js';

runOsvDistroSweep('Debian', 'Debian').catch(err => {
  console.error(err);
  process.exit(1);
});
