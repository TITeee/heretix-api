/**
 * NVD CPE product name aliases
 *
 * NVD sometimes uses multiple product names for the same software.
 * This is especially common after vendor acquisitions when naming conventions change
 * (e.g., F5's acquisition of NGINX).
 *
 * This file manages the mapping from "canonical name used when searching" →
 * "list of product names stored in NVD".
 *
 * How to add:
 *   Use the canonical name (lowercase) as the key, and list all product names
 *   that appear in NVD CPEs. Always include the canonical name itself in the list.
 *   Verify that alias targets actually exist in NVDAffectedPackage before adding.
 */
export const PRODUCT_ALIASES: Record<string, string[]> = {
  // ── nginx ──────────────────────────────────────────────────────────────────
  // After F5 acquired NGINX, the NVD CPE product name changed.
  // Old: nginx:nginx / New: f5:nginx_open_source, f5:nginx_open_source_subscription
  nginx: [
    'nginx',
    'nginx_open_source',
    'nginx_open_source_subscription',
  ],

  // ── OpenSSL ────────────────────────────────────────────────────────────────
  openssl: ['openssl'],

  // ── Apache HTTP Server ─────────────────────────────────────────────────────
  // NVD uses apache:httpd consistently.
  // http_server is used by oracle:http_server (Oracle HTTP Server) so it is excluded
  // to prevent Oracle products from appearing in packageName searches without a vendor filter.
  httpd: ['httpd'],

  // ── Apache Tomcat ──────────────────────────────────────────────────────────
  // NVD uses apache:tomcat consistently. Version-specific names (tomcat7/8/9/10)
  // were verified to be absent from the DB.
  tomcat: ['tomcat'],

  // ── curl / libcurl ─────────────────────────────────────────────────────────
  curl: ['curl', 'libcurl'],

  // ── Varnish ────────────────────────────────────────────────────────────────
  varnish: ['varnish', 'varnish_cache'],

  // ── Java (JRE / JDK) ───────────────────────────────────────────────────────
  // jre and jdk are interchangeable Sun/Oracle product names for the same runtime.
  // openjdk is kept separate: old NVD entries use openjdk:* with no version bounds,
  // which would cause false positives if cross-linked with jre/jdk aliases.
  // DB counts: jre=28,573 / jdk=24,225 / openjdk=6,026
  java: ['jre', 'jdk'],
  jre: ['jre', 'jdk'],
  jdk: ['jre', 'jdk'],

  // ── Adobe Acrobat ──────────────────────────────────────────────────────────
  // NVD uses four distinct product names across Acrobat generations.
  // DB counts: acrobat=12,338 / acrobat_reader=10,263 / acrobat_dc=4,391 / acrobat_reader_dc=4,376
  acrobat: ['acrobat', 'acrobat_dc', 'acrobat_reader', 'acrobat_reader_dc'],
  acrobat_reader: ['acrobat', 'acrobat_dc', 'acrobat_reader', 'acrobat_reader_dc'],

  // ── Opera ──────────────────────────────────────────────────────────────────
  // NVD uses opera_browser (20,879) and opera (653) as distinct product names.
  opera: ['opera', 'opera_browser'],

  // ── macOS ──────────────────────────────────────────────────────────────────
  // NVD renamed mac_os_x to macos. DB counts: mac_os_x=18,211 / macos=4,327
  macos: ['macos', 'mac_os_x'],
  mac_os_x: ['macos', 'mac_os_x'],

  // ── Joomla ─────────────────────────────────────────────────────────────────
  // NVD uses joomla! (with exclamation mark, 2,906) and joomla (419).
  joomla: ['joomla', 'joomla!'],

  // ── Docker ─────────────────────────────────────────────────────────────────
  // Docker Desktop is registered as a separate product name.
  // DB counts: docker=261 / docker_desktop=16
  docker: ['docker', 'docker_desktop'],

  // ── Spring Framework ───────────────────────────────────────────────────────
  // NVD uses spring_framework (373). The short name "spring" is not a CPE product name.
  spring: ['spring_framework'],
  spring_framework: ['spring_framework'],

  // ── PostgreSQL ─────────────────────────────────────────────────────────────
  // Common abbreviation mapping. DB count: postgresql=3,624
  postgres: ['postgresql'],

  // ── Kubernetes ─────────────────────────────────────────────────────────────
  // k8s is a widely used abbreviation. DB count: kubernetes=275
  k8s: ['kubernetes'],
};

/**
 * Return the list of NVD product names corresponding to a search term.
 * If no alias is defined, returns only the original name.
 *
 * @example
 * expandProductAliases('nginx')
 * // → ['nginx', 'nginx_open_source', 'nginx_open_source_subscription']
 *
 * expandProductAliases('unknown-tool')
 * // → ['unknown-tool']
 */
export function expandProductAliases(product: string): string[] {
  return PRODUCT_ALIASES[product.toLowerCase()] ?? [product];
}
