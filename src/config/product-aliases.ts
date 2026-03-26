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
  // Unified as openssl:openssl, listed for completeness
  openssl: ['openssl'],

  // ── Apache HTTP Server ─────────────────────────────────────────────────────
  // NVD uses apache:httpd consistently.
  // http_server is used by oracle:http_server (Oracle HTTP Server) so it is excluded
  // from aliases to prevent Oracle products from appearing in packageName searches without a vendor filter.
  httpd: ['httpd'],

  // ── Apache Tomcat ──────────────────────────────────────────────────────────
  // NVD uses apache:tomcat consistently, but older entries may include tomcat9 etc.
  tomcat: ['tomcat', 'tomcat9'],

  // ── curl ───────────────────────────────────────────────────────────────────
  curl: ['curl', 'libcurl'],

  // ── varnish ───────────────────────────────────────────────────────────────────
  varnish: ['varnish', 'varnish_cache'],
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
