/**
 * WordPress core, plugins and themes, as heretix names them.
 *
 * There is no OSV ecosystem or registered PURL type for WordPress, so heretix uses its own:
 * the ecosystem `WordPress`, and a package named after the kind of software and its
 * wordpress.org slug, which is also the name of its directory on a site:
 *
 *   core:wordpress     WordPress itself
 *   plugin:<slug>      wp-content/plugins/<slug>
 *   theme:<slug>       wp-content/themes/<slug>
 *
 * heretix-cli writes them as `pkg:wordpress/<kind>/<slug>@<version>`, which heretix-management
 * turns back into `<kind>:<slug>`. Their only data source is the Wordfence feed
 * (worker/wordfence-fetcher.ts), stored as vendor-advisory rows under WORDPRESS_VENDOR.
 */

export const WORDPRESS_ECOSYSTEM = 'WordPress';

/** AdvisoryAffectedProduct.vendor of the Wordfence rows. */
export const WORDPRESS_VENDOR = 'wordpress';

/** The package name of a piece of WordPress software: `plugin:akismet`. */
export function wordpressProductName(kind: string, slug: string): string {
  return `${kind}:${slug}`;
}

export function isWordPressEcosystem(eco: string | undefined): boolean {
  return eco === WORDPRESS_ECOSYSTEM;
}
