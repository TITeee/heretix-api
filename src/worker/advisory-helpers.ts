/**
 * Pure advisory-import decision logic extracted from advisory-fetcher.ts
 * for unit testability. No DB dependency.
 */

/**
 * PostgreSQL on RHEL/Oracle Linux ships as parallel DNF module streams
 * (postgresql:12/:13/:15/:16/:17/:18 coexisting under one product name).
 * The OVAL "earlier than X" criteria RedHatFetcher/OracleLinuxFetcher parse
 * carry no lower bound, so a newer stream's fix silently swallows queries
 * for an older, unrelated stream (confirmed: CVE-2026-6476 only affects
 * PostgreSQL 17+ per its own description, but matched a 16.4 query because
 * the only recorded fix was "earlier than 18.4..." with no floor).
 *
 * Infer each row's own major-version floor when the vendor doesn't provide
 * one. Scoped to exactly product "postgresql" — verified safe via real data
 * (6 parallel streams, each cleanly starting at X.0) and empirically
 * measured via `pnpm validate:postgresql` (see ACCURACY.md). NOT
 * generalized to other module-stream products (nodejs, mariadb, php, ruby,
 * redis, podman, qemu-kvm, libvirt, etc.) — same architecture, but without
 * the same accuracy-validation tooling to confirm the heuristic actually
 * helps there before applying it.
 */
export function inferPostgresqlModuleVersionStart(
  product: string,
  versionStart: string | undefined,
  versionEnd: string | undefined,
): string | undefined {
  if (versionStart || product !== 'postgresql' || !versionEnd?.includes('.module+')) {
    return versionStart;
  }
  const major = versionEnd.match(/^(\d+)\./)?.[1];
  return major ? `${major}.0` : versionStart;
}
