/**
 * Ubuntu OSV search accuracy validation script.
 * See src/scripts/lib/osv-distro-sweep.ts for the shared sweep methodology.
 *
 * Usage:
 *   pnpm validate:ubuntu
 */
import { runOsvDistroSweep } from './lib/osv-distro-sweep.js';

runOsvDistroSweep('Ubuntu', 'Ubuntu').catch(err => {
  console.error(err);
  process.exit(1);
});
