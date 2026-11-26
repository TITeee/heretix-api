/**
 * AlmaLinux/Rocky Linux vs borrowed Red Hat data: agreement check
 *
 * Neither AlmaLinux nor Rocky Linux publish an unfixed/deferred/will-not-fix
 * status of their own (confirmed 2026-11-26: errata.almalinux.org and
 * errata.rockylinux.org list only published, fixed errata). Both are binary
 * rebuilds of the matching RHEL major, so rpmAdvisoryVendor() in
 * search-helpers.ts routes their queries to Red Hat's own OVAL/VEX rows
 * ('red-hat-<major>') as a best-effort proxy -- a judgement Red Hat made, not
 * one AlmaLinux/Rocky published themselves, so this must stay accurate.
 *
 * There is no independent ground truth for the unfixed population either
 * distro doesn't publish (that is the entire problem). This script instead
 * measures agreement on the population where AlmaLinux/Rocky DO publish a
 * verdict -- their own OSV "fixed" rows -- by asking, for the exact version
 * each distro's own OSV data says is fixed, whether Red Hat's borrowed rows
 * (run through the real matchesRpmVersionRange(), not a reimplemented
 * comparison) also judge that version not vulnerable. Disagreement here means
 * the borrowed data would wrongly keep an already-fixed package flagged.
 *
 * Reported, but excluded from the pass/fail gate: modular packages (php,
 * nodejs, ... -- RHEL 8/9 AppStream only, dropped in RHEL 10). AlmaLinux and
 * Rocky each assign their own independent module build+hash counter after
 * the stream tag ("module_el9.2.0+24+9207bbc0" vs Red Hat's own
 * "module+el9.2.0+17911+b059dfc2"), which is not numerically comparable
 * across vendors and also needs picking the right one of several parallel
 * module streams -- a known, out-of-scope gap (isBorrowedRedHatModuleBuild()
 * keeps these queries off the live search path entirely). Measured
 * 2026-11-26: module agreement 18-64% depending on major; see the PR this
 * script shipped with for the full numbers.
 *
 * Usage:
 *   pnpm validate:almalinux-redhat             # both distros, every major
 *   pnpm validate:almalinux-redhat almalinux   # one distro only
 */
import 'dotenv/config';
import { prisma, closeDb } from '../db/client.js';
import { matchesRpmVersionRange } from '../utils/search-helpers.js';

const MAJORS = ['8', '9', '10'];
// Below this, something regressed -- the measured baseline (2026-11-26) is
// 88-97% across both distros and every major for non-module packages.
const MIN_NON_MODULE_AGREEMENT = 0.80;
// Below this, Red Hat's data covers too little of what AlmaLinux/Rocky
// actually ship fixes for to be worth borrowing at all for this major.
const MIN_COVERAGE = 0.60;

const MODULE_BUILD_PATTERN = /\.module[_+]el\d/i;

interface Row {
  almaFixedPairs: number;
  noRhCoverage: number;
  coverageRate: number;
  nonModuleAgree: number;
  nonModuleDisagree: number;
  nonModuleAgreementRate: number | null;
  moduleAgree: number;
  moduleDisagree: number;
  moduleAgreementRate: number | null;
  disagreeSample: { cve: string; pkg: string; fixedVersion: string }[];
}

async function checkDistro(ecosystemBase: 'AlmaLinux' | 'Rocky Linux'): Promise<boolean> {
  console.log(`\n=== ${ecosystemBase} ===`);
  let ok = true;

  for (const major of MAJORS) {
    const ecosystem = `${ecosystemBase}:${major}`;
    const vendor = `red-hat-${major}`;

    const almaFixed = (await prisma.oSVAffectedPackage.findMany({
      where: { ecosystem, fixedVersion: { not: null } },
      select: { packageName: true, fixedVersion: true, vulnerability: { select: { cveId: true } } },
    })).filter((r): r is typeof r & { packageName: string; fixedVersion: string; vulnerability: { cveId: string } } =>
      !!r.vulnerability.cveId && !!r.packageName && !!r.fixedVersion);

    if (almaFixed.length === 0) {
      console.log(`${major}: no ${ecosystem} OSV rows with a fixed version locally -- skipped`);
      continue;
    }

    const cveIds = [...new Set(almaFixed.map(r => r.vulnerability.cveId))];
    const rhRows = await prisma.advisoryAffectedProduct.findMany({
      where: { vendor, advisory: { cveId: { in: cveIds } } },
      select: { product: true, versionStart: true, versionEnd: true, patchAvailable: true, streamFixes: true, advisory: { select: { cveId: true } } },
    });
    const rhByKey = new Map<string, typeof rhRows>();
    for (const r of rhRows) {
      const key = `${r.advisory.cveId}::${r.product}`;
      (rhByKey.get(key) ?? rhByKey.set(key, []).get(key)!).push(r);
    }

    const row: Row = {
      almaFixedPairs: almaFixed.length, noRhCoverage: 0, coverageRate: 0,
      nonModuleAgree: 0, nonModuleDisagree: 0, nonModuleAgreementRate: null,
      moduleAgree: 0, moduleDisagree: 0, moduleAgreementRate: null,
      disagreeSample: [],
    };

    for (const r of almaFixed) {
      const rh = rhByKey.get(`${r.vulnerability.cveId}::${r.packageName}`);
      if (!rh || rh.length === 0) { row.noRhCoverage++; continue; }

      const isModule = MODULE_BUILD_PATTERN.test(r.fixedVersion);
      const stillVulnerable = rh.some(x => matchesRpmVersionRange(x, r.fixedVersion));
      if (isModule) {
        if (stillVulnerable) row.moduleDisagree++; else row.moduleAgree++;
      } else {
        if (stillVulnerable) {
          row.nonModuleDisagree++;
          if (row.disagreeSample.length < 5) {
            row.disagreeSample.push({ cve: r.vulnerability.cveId, pkg: r.packageName, fixedVersion: r.fixedVersion });
          }
        } else row.nonModuleAgree++;
      }
    }

    const covered = row.almaFixedPairs - row.noRhCoverage;
    row.coverageRate = covered / row.almaFixedPairs;
    const nonModuleCovered = row.nonModuleAgree + row.nonModuleDisagree;
    row.nonModuleAgreementRate = nonModuleCovered === 0 ? null : row.nonModuleAgree / nonModuleCovered;
    const moduleCovered = row.moduleAgree + row.moduleDisagree;
    row.moduleAgreementRate = moduleCovered === 0 ? null : row.moduleAgree / moduleCovered;

    const belowCoverage = row.coverageRate < MIN_COVERAGE;
    const belowAgreement = row.nonModuleAgreementRate !== null && row.nonModuleAgreementRate < MIN_NON_MODULE_AGREEMENT;
    if (belowCoverage || belowAgreement) ok = false;

    console.log(
      `${major}: coverage ${(row.coverageRate * 100).toFixed(0)}%` +
      ` (${belowCoverage ? 'BELOW' : 'ok'} ${MIN_COVERAGE * 100}% floor),` +
      ` non-module agreement ${row.nonModuleAgreementRate === null ? 'n/a' : (row.nonModuleAgreementRate * 100).toFixed(0) + '%'}` +
      ` (${belowAgreement ? 'BELOW' : 'ok'} ${MIN_NON_MODULE_AGREEMENT * 100}% floor),` +
      ` module agreement ${row.moduleAgreementRate === null ? 'n/a' : (row.moduleAgreementRate * 100).toFixed(0) + '%'} (reported only, out of scope)`,
    );
    for (const s of row.disagreeSample) {
      console.log(`       disagreement: ${s.cve} ${s.pkg} (${ecosystemBase} says fixed at ${s.fixedVersion})`);
    }
  }

  return ok;
}

async function main(): Promise<void> {
  const requested = process.argv[2];
  const distros: Array<'AlmaLinux' | 'Rocky Linux'> =
    requested === 'almalinux' ? ['AlmaLinux']
    : requested === 'rocky' ? ['Rocky Linux']
    : ['AlmaLinux', 'Rocky Linux'];

  let ok = true;
  for (const distro of distros) {
    if (!(await checkDistro(distro))) ok = false;
  }

  if (!ok) {
    console.log('\nSome majors fell below the agreement/coverage floor -- see BELOW markers above.');
    process.exitCode = 1;
  }
}

main()
  .catch(err => { console.error(err); process.exitCode = 1; })
  .finally(() => closeDb());
