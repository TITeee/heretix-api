/**
 * Alpine OSV search accuracy validation script.
 * See src/scripts/lib/osv-distro-sweep.ts for the shared sweep methodology.
 *
 * Usage:
 *   pnpm validate:alpine
 */
import { runOsvDistroSweep } from './lib/osv-distro-sweep.js';

runOsvDistroSweep('Alpine', 'Alpine').catch(err => {
  console.error(err);
  process.exit(1);
});
