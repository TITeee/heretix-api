import { defineConfig } from 'vitest/config';

const testDbUrl = process.env.TEST_DATABASE_URL;
if (!testDbUrl) {
  throw new Error(
    'TEST_DATABASE_URL is not set. Point it at a disposable Postgres database, ' +
    'e.g. postgresql://postgres:***@localhost:5432/heretix_test',
  );
}

export default defineConfig({
  test: {
    globals: true,
    include: ['src/**/*.integration.test.ts'],
    env: { DATABASE_URL: testDbUrl, API_KEY: 'test-api-key' },
    // All integration test files share one truncated DB — running them
    // concurrently would race on beforeEach() resets.
    fileParallelism: false,
    testTimeout: 15000,
    hookTimeout: 15000,
  },
});
