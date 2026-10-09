import { describe, it, expect, vi, beforeEach } from 'vitest';

// fetch() reads the sitemaps over HTTP and renders each article in a headless
// browser; both are replaced here so the control flow can be tested: what is
// thrown, what is counted, and what is returned alongside the curated entries.
// The browser stand-in runs the real page callback of renderArticle() against a
// fake page, so its normalization and its "CVE table without a version table"
// check are exercised too.
const get = vi.fn();
const rendered = vi.fn();
const withPage = vi.fn(async (url: string, fn: (page: unknown) => Promise<unknown>) => {
  const article = await rendered(url);
  const page = {
    waitForFunction: async () => {},
    evaluate: async () => ({ bodyText: article.bodyText, tables: article.tables }),
  };
  return fn(page);
});
vi.mock('axios', () => ({ default: { get } }));
vi.mock('../utils/browser.js', () => ({ withPage, closeBrowser: vi.fn(async () => {}) }));

const { IvantiFetcher } = await import('./ivanti-fetcher.js');

const INDEX = '<sitemapindex><sitemap><loc>https://hub.ivanti.com/s/sitemap-topicarticle-1.xml</loc></sitemap></sitemapindex>';
const SITEMAP = (names: string[]) => `<urlset>${names.map(n => `<url><loc>https://hub.ivanti.com/s/article/${n}?language=en_US</loc></url>`).join('')}</urlset>`;

function serve(names: string[]) {
  get.mockImplementation(async (url: string) => ({ data: url.endsWith('/s/sitemap.xml') ? INDEX : SITEMAP(names) }));
}

const GOOD = {
  url: 'u', urlName: 'Security-Advisory-Ivanti-Sentry-CVE-2026-0001',
  bodyText: 'Security Advisory Ivanti Sentry (CVE-2026-0001)\nPrimary Product\nSentry\nCreated Date\nJan 1, 2026 1:00:00 AM',
  tables: [
    [['CVE Number', 'Description', 'CVSS Score (Severity)', 'CVSS Vector', 'CWE'], ['CVE-2026-0001', 'd', '8.1 (High)', 'v', 'CWE-1']],
    [['Product Name', 'Affected Version(s)', 'Resolved Version(s)', 'Patch Availability'], ['Ivanti Sentry', 'R10.8.1 and prior', 'R10.8.2', 'x']],
  ],
};

beforeEach(() => { get.mockReset(); rendered.mockReset(); withPage.mockClear(); });

describe('IvantiFetcher.fetch', () => {
  it('lists the Security-Advisory articles of every article sitemap, and only those', async () => {
    serve(['Security-Advisory-Ivanti-Sentry-CVE-2026-0001', 'How-to-find-the-serial-number', 'SA44101']);
    rendered.mockResolvedValue(GOOD);
    const fetcher = new IvantiFetcher();
    await fetcher.fetch();
    expect(withPage).toHaveBeenCalledTimes(1);
    expect(withPage.mock.calls[0][0]).toBe('https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Sentry-CVE-2026-0001');
  });

  it('returns the advisories it read together with the curated ones', async () => {
    serve(['Security-Advisory-Ivanti-Sentry-CVE-2026-0001']);
    rendered.mockResolvedValue(GOOD);
    const advisories = await new IvantiFetcher().fetch();
    const ids = advisories.map(a => a.externalId);
    expect(ids).toContain('Security-Advisory-Ivanti-Sentry-CVE-2026-0001/CVE-2026-0001');
    expect(ids).toContain('SA44101/CVE-2019-11510');
  });

  it('counts an article that failed to render, and still returns the rest', async () => {
    serve(['Security-Advisory-A', 'Security-Advisory-B']);
    rendered.mockRejectedValueOnce(new Error('timeout')).mockResolvedValueOnce(GOOD);
    const fetcher = new IvantiFetcher();
    const advisories = await fetcher.fetch();
    expect(fetcher.fetchFailedCount()).toBe(1);
    // The article that rendered is the second one listed; its id comes from the name in the sitemap.
    expect(advisories.some(a => a.externalId === 'Security-Advisory-B/CVE-2026-0001')).toBe(true);
  });

  it('throws when nothing could be read from the site, rather than succeeding on the curated entries alone', async () => {
    // The curated entries are always returned. If they were enough for a fetch to count
    // as successful, a layout change would go unnoticed and pruning would delete what the
    // site gave us earlier.
    serve(['Security-Advisory-A', 'Security-Advisory-B']);
    rendered.mockRejectedValue(new Error('layout changed'));
    const fetcher = new IvantiFetcher();
    await expect(fetcher.fetch()).rejects.toThrow(/no advisory could be read/);
    expect(fetcher.fetchFailedCount()).toBe(2);
  });

  it('throws when the sitemap index lists no article sitemaps', async () => {
    get.mockResolvedValue({ data: '<sitemapindex></sitemapindex>' });
    await expect(new IvantiFetcher().fetch()).rejects.toThrow(/no article sitemaps/);
  });

  it('does not count an older-format article (no standard CVE table) as a failure', async () => {
    serve(['Security-Advisory-A', 'Security-Advisory-B']);
    const legacyLayout = { ...GOOD, tables: [[['CVE', 'Description', 'CVSS', 'Vector'], ['CVE-2024-1', 'd', '8', 'v']]] };
    rendered.mockResolvedValueOnce(legacyLayout).mockResolvedValueOnce(GOOD);
    const fetcher = new IvantiFetcher();
    await fetcher.fetch();
    expect(fetcher.fetchFailedCount()).toBe(0);
  });
});
