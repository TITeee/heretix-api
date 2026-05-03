import { chromium as playwrightChromium, type Browser, type Page } from 'playwright';
import { chromium as extraChromium } from 'playwright-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import { logger } from './logger.js';

extraChromium.use(StealthPlugin());

let browser: Browser | null = null;

async function getBrowser(): Promise<Browser> {
  if (!browser || !browser.isConnected()) {
    logger.debug('Launching stealth headless Chromium');
    // playwright-extra returns a Playwright-compatible Browser
    browser = await extraChromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
      ],
    }) as unknown as Browser;
  }
  return browser;
}

/**
 * Open a new page, navigate to the URL, wait for DOM to settle,
 * run the provided function, then close the page.
 *
 * Uses playwright-extra with stealth plugin to reduce bot detection.
 * The browser process is a lazy singleton — call closeBrowser() when done.
 */
export async function withPage<T>(
  url: string,
  fn: (page: Page) => Promise<T>,
  { timeout = 30000 }: { timeout?: number } = {},
): Promise<T> {
  const b = await getBrowser();
  const context = await b.newContext({
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    locale: 'en-US',
    timezoneId: 'America/New_York',
    viewport: { width: 1280, height: 800 },
  });
  const page = await context.newPage();
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
    return await fn(page);
  } finally {
    await page.close();
    await context.close();
  }
}

/** Close the shared browser. Call once after a batch of scraping is complete. */
export async function closeBrowser(): Promise<void> {
  if (browser) {
    await browser.close();
    browser = null;
    logger.debug('Headless browser closed');
  }
}

// Re-export for callers that need the plain Playwright chromium
export { playwrightChromium as chromium };
