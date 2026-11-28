import { describe, it, expect, beforeEach, afterAll, beforeAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { prisma } from '../../db/client.js';
import { resetDb } from '../../test-utils/db.js';
import { createServer } from '../server.js';
import { importAdvisoryData } from '../../worker/advisory-fetcher.js';
import { normalizeWordfenceRecord, WORDFENCE_SOURCE, type WordfenceRecord } from '../../worker/wordfence-fetcher.js';

const API_KEY = 'test-api-key'; // matches vitest.integration.config.ts

async function search(app: FastifyInstance, query: string) {
  const res = await app.inject({
    method: 'GET',
    url: `/api/v1/vulnerabilities/search?${query}`,
    headers: { 'x-api-key': API_KEY },
  });
  return { status: res.statusCode, body: res.json() };
}

async function importRecord(rec: WordfenceRecord) {
  const { advisory } = normalizeWordfenceRecord(rec);
  await importAdvisoryData(advisory!, WORDFENCE_SOURCE);
}

const base = { copyrights: { defiant: { notice: 'Copyright 2012-2026 Defiant Inc.' } }, published: '2026-11-04 00:00:00' };

const wpvivid: WordfenceRecord = {
  ...base,
  id: '000229b1-9ea9-4303-a79b-9ff24d1a8532',
  title: 'WPvivid < 0.9.138 - Path Traversal',
  cve: 'CVE-2026-115426',
  cvss: { score: 4.9, rating: 'Medium', vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N' },
  software: [{
    type: 'plugin', slug: 'wpvivid-backuprestore', patched: true, patched_versions: ['0.9.138'],
    affected_versions: { '[*, 0.9.138)': { from_version: '*', from_inclusive: true, to_version: '0.9.138', to_inclusive: false } },
  }],
};

const coreMultiBranch: WordfenceRecord = {
  ...base,
  id: '0114f098-713d-4eef-8643-901f607375de',
  title: 'WordPress Core 4.1 - 5.8.2 - SQL Injection',
  cve: 'CVE-2022-21664',
  cvss: { score: 8.8, rating: 'High' },
  software: [{
    type: 'core', slug: 'wordpress', patched: true, patched_versions: ['4.1.34', '4.2.31'],
    affected_versions: {
      '[4.1, 4.1.34)': { from_version: '4.1', from_inclusive: true, to_version: '4.1.34', to_inclusive: false },
      '[4.2, 4.2.31)': { from_version: '4.2', from_inclusive: true, to_version: '4.2.31', to_inclusive: false },
    },
  }],
};

const unpatchedTheme: WordfenceRecord = {
  ...base,
  id: '0099c700-e1af-4d97-a518-151a9139ea35',
  title: 'AIHub <= * - Missing Authorization',
  cve: 'CVE-2025-0951',
  cvss: { score: 5.3, rating: 'Medium' },
  software: [{
    type: 'theme', slug: 'aihub', patched: false, patched_versions: [],
    affected_versions: { '*': { from_version: '*', from_inclusive: true, to_version: '*', to_inclusive: true } },
  }],
};

describe('search: WordPress core, plugins and themes (Wordfence)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await createServer();
  });

  beforeEach(async () => {
    await resetDb();
    for (const rec of [wpvivid, coreMultiBranch, unpatchedTheme]) await importRecord(rec);
  });

  afterAll(async () => {
    await app.close();
    await prisma.$disconnect();
  });

  it('finds a plugin below its fix, with the fix and the Wordfence source, and not at the fix', async () => {
    const below = await search(app, 'package=plugin:wpvivid-backuprestore&version=0.9.137&ecosystem=WordPress');
    expect(below.status).toBe(200);
    expect(below.body.results).toHaveLength(1);
    expect(below.body.results[0]).toMatchObject({ externalId: 'CVE-2026-115426', fixedVersion: '0.9.138', sources: [WORDFENCE_SOURCE] });

    const fixed = await search(app, 'package=plugin:wpvivid-backuprestore&version=0.9.138&ecosystem=WordPress');
    expect(fixed.body.results).toHaveLength(0);
  });

  it('takes the ecosystem as heretix-cli may spell it', async () => {
    const { body } = await search(app, 'package=plugin:wpvivid-backuprestore&version=0.9.1&ecosystem=wordpress');
    expect(body.results).toHaveLength(1);
  });

  it('matches core per branch and gives that branch its own fix', async () => {
    const b41 = await search(app, 'package=core:wordpress&version=4.1.20&ecosystem=WordPress');
    expect(b41.body.results[0]).toMatchObject({ externalId: 'CVE-2022-21664', fixedVersion: '4.1.34' });
    const b42 = await search(app, 'package=core:wordpress&version=4.2.30&ecosystem=WordPress');
    expect(b42.body.results[0]).toMatchObject({ fixedVersion: '4.2.31' });
    const fixed = await search(app, 'package=core:wordpress&version=4.2.31&ecosystem=WordPress');
    expect(fixed.body.results).toHaveLength(0);
  });

  it('reports an unpatched theme at any version, with no fix', async () => {
    const { body } = await search(app, 'package=theme:aihub&version=2.0.0&ecosystem=WordPress');
    expect(body.results).toHaveLength(1);
    expect(body.results[0].fixedVersion ?? null).toBeNull();
  });

  it('does not give a WordPress search the rows of another vendor with the same product name', async () => {
    await importAdvisoryData({
      externalId: 'OTHER-1',
      cveId: 'CVE-2026-000001',
      severity: 'HIGH',
      affectedProducts: [{ vendor: 'someone', product: 'plugin:wpvivid-backuprestore', versionEnd: '9.0' }],
      rawData: {},
    }, 'advisory-other');
    const { body } = await search(app, 'package=plugin:wpvivid-backuprestore&version=0.9.137&ecosystem=WordPress');
    expect(body.results.map((r: { externalId: string }) => r.externalId)).toEqual(['CVE-2026-115426']);
  });

  it('keeps the record, its copyright notices with it, for GET /vulnerabilities/:id', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/vulnerabilities/CVE-2026-115426', headers: { 'x-api-key': API_KEY } });
    expect(res.statusCode).toBe(200);
    const adv = res.json().advisoryVulnerabilities.find((a: { source: string }) => a.source === WORDFENCE_SOURCE);
    expect(adv.url).toBe(`https://www.wordfence.com/threat-intel/vulnerabilities/id/${wpvivid.id}`);
    expect(adv.rawData.copyrights).toEqual(base.copyrights);
  });
});
