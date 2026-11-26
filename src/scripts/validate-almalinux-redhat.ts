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
 * also judge that version not vulnerable, using the exact matching functions
 * the live search path uses (matchesRpmVersionRange() for an ordinary
 * package, matchesBorrowedModuleBuild() for a modular one -- php, nodejs,
 * ... -- see its comment), never a reimplemented comparison. Disagreement
 * here means the borrowed data would wrongly keep an already-fixed package
 * flagged; a low coverage rate (no Red Hat row at all, or no row sharing the
 * query's own module stream) just means the gap stays unfilled, same as
 * before this borrowing existed -- it costs nothing by itself.
 *
 * Usage:
 *   pnpm validate:almalinux-redhat             # both distros, every major
 *   pnpm validate:almalinux-redhat almalinux   # one distro only
 */
import 'dotenv/config';
import { prisma, closeDb } from '../db/client.js';
import { matchesRpmVersionRange, matchesBorrowedModuleBuild, moduleStreamTag } from '../utils/search-helpers.js';

const MAJORS = ['8', '9', '10'];
// Below this, something regressed -- the measured baseline (2026-11-26) is
// 88-97% for non-module packages, 78-87% for modular ones, across both
// distros and every major.
const MIN_NON_MODULE_AGREEMENT = 0.80;
const MIN_MODULE_AGREEMENT = 0.70;
// Below this, Red Hat's data covers too little of what AlmaLinux/Rocky
// actually ship fixes for to be worth borrowing at all for this major.
// Modular coverage runs lower by nature (point-release timing, see the
// module comment on RPM_ECOSYSTEM_VENDOR in search-helpers.ts) and is not
// gated the same way -- a low rate there just means fewer of this major's
// modular packages get the benefit, not a wrong answer.
const MIN_COVERAGE = 0.60;

const MODULE_BUILD_PATTERN = /\.module[_+]el\d/i;

interface Row {
  almaFixedPairs: number;
  noRhCoverage: number;
  coverageRate: number;
  nonModuleAgree: number;
  nonModuleDisagree: number;
  nonModuleAgreementRate: number | null;
  moduleCoveredPairs: number;
  moduleNoCoverage: number;
  moduleAgree: number;
  moduleDisagree: number;
  moduleAgreementRate: number | null;
  disagreeSample: { cve: string; pkg: string; fixedVersion: string; isModule: boolean }[];
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
      moduleCoveredPairs: 0, moduleNoCoverage: 0, moduleAgree: 0, moduleDisagree: 0, moduleAgreementRate: null,
      disagreeSample: [],
    };

    for (const r of almaFixed) {
      const rh = rhByKey.get(`${r.vulnerability.cveId}::${r.packageName}`);
      const isModule = MODULE_BUILD_PATTERN.test(r.fixedVersion);

      if (!rh || rh.length === 0) {
        if (isModule) row.moduleNoCoverage++; else row.noRhCoverage++;
        continue;
      }

      if (isModule) {
        // "Covered" means some row even speaks to this query's module stream:
        // either an unconditional "confirmed unfixed" row (no versionEnd,
        // applies regardless of stream) or one whose own versionEnd carries
        // the same stream tag as the query (matchesBorrowedModuleBuild()
        // rejects any other stream on its own, see its comment).
        const queryStream = moduleStreamTag(r.fixedVersion);
        const sameStreamRow = rh.some(x => (!x.versionEnd && x.patchAvailable === false) || moduleStreamTag(x.versionEnd) === queryStream);
        if (!sameStreamRow) { row.moduleNoCoverage++; continue; }

        row.moduleCoveredPairs++;
        const stillVulnerable = rh.some(x => matchesBorrowedModuleBuild(x, r.fixedVersion));
        if (stillVulnerable) {
          row.moduleDisagree++;
          if (row.disagreeSample.length < 8) {
            row.disagreeSample.push({ cve: r.vulnerability.cveId, pkg: r.packageName, fixedVersion: r.fixedVersion, isModule: true });
          }
        } else row.moduleAgree++;
      } else {
        const stillVulnerable = rh.some(x => matchesRpmVersionRange(x, r.fixedVersion));
        if (stillVulnerable) {
          row.nonModuleDisagree++;
          if (row.disagreeSample.length < 8) {
            row.disagreeSample.push({ cve: r.vulnerability.cveId, pkg: r.packageName, fixedVersion: r.fixedVersion, isModule: false });
          }
        } else row.nonModuleAgree++;
      }
    }

    const nonModuleTotal = row.nonModuleAgree + row.nonModuleDisagree + row.noRhCoverage;
    const covered = row.nonModuleAgree + row.nonModuleDisagree;
    row.coverageRate = nonModuleTotal === 0 ? 1 : covered / nonModuleTotal;
    row.nonModuleAgreementRate = covered === 0 ? null : row.nonModuleAgree / covered;
    row.moduleAgreementRate = row.moduleCoveredPairs === 0 ? null : row.moduleAgree / row.moduleCoveredPairs;

    const belowCoverage = row.coverageRate < MIN_COVERAGE;
    const belowNonModuleAgreement = row.nonModuleAgreementRate !== null && row.nonModuleAgreementRate < MIN_NON_MODULE_AGREEMENT;
    const belowModuleAgreement = row.moduleAgreementRate !== null && row.moduleAgreementRate < MIN_MODULE_AGREEMENT;
    if (belowCoverage || belowNonModuleAgreement || belowModuleAgreement) ok = false;

    console.log(
      `${major}: non-module coverage ${(row.coverageRate * 100).toFixed(0)}%` +
      ` (${belowCoverage ? 'BELOW' : 'ok'} ${MIN_COVERAGE * 100}% floor),` +
      ` agreement ${row.nonModuleAgreementRate === null ? 'n/a' : (row.nonModuleAgreementRate * 100).toFixed(0) + '%'}` +
      ` (${belowNonModuleAgreement ? 'BELOW' : 'ok'} ${MIN_NON_MODULE_AGREEMENT * 100}% floor)`,
    );
    const moduleTotal = row.moduleAgree + row.moduleDisagree + row.moduleNoCoverage;
    console.log(
      `     module coverage ${moduleTotal === 0 ? 'n/a' : ((row.moduleCoveredPairs / moduleTotal) * 100).toFixed(0) + '%'},` +
      ` agreement ${row.moduleAgreementRate === null ? 'n/a' : (row.moduleAgreementRate * 100).toFixed(0) + '%'}` +
      ` (${belowModuleAgreement ? 'BELOW' : 'ok'} ${MIN_MODULE_AGREEMENT * 100}% floor)`,
    );
    for (const s of row.disagreeSample) {
      console.log(`       disagreement${s.isModule ? ' (module)' : ''}: ${s.cve} ${s.pkg} (${ecosystemBase} says fixed at ${s.fixedVersion})`);
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
