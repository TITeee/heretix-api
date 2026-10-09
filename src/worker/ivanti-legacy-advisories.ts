import type { NormalizedAdvisory } from './advisory-fetcher.js';
import { IVANTI_VENDOR } from '../utils/advisory-version.js';

// Ivanti advisories published before its current article template.
//
// ivanti-fetcher.ts reads the "Affected Versions" table of the current template.
// The articles below predate it: SA4xxxx bulletins from Pulse Secure (2019-2021)
// and the January 2024 Connect Secure articles. Their affected and fixed versions
// sit in prose, in lists inside a sentence, or in tables whose shape differs from
// article to article, so there is nothing to parse generically -- a parser for one
// article reads the next one wrong. They are historical records that no longer
// change (Pulse Connect Secure 8.x/9.x is end of support), so they are kept here
// as data, read once from the article, each with its source.
//
// Which ones: the Ivanti entries of CISA's Known Exploited Vulnerabilities catalog
// that no other source gave a fixed version for, and the other Pulse Secure
// bulletins from 2019 on that name a version (a fix, or the last affected one).
// Bulletins from 2018 and earlier are left out: those products are long out of
// support. So are the 2019-2021 bulletins that name no version -- products
// "Not Vulnerable", "Vulnerable" with no release, "Under review", or an
// OpenSSL/kernel/malware notice with nothing to match a version against.
//
// Not covered: CVE-2021-44529 (Endpoint Manager Cloud Services Appliance), which
// has no article on the hub, and CVE-2023-38035 (Sentry) only up to its affected
// versions, since its fix is an RPM script per version rather than a version.
// Of the third-party notices, only the Pulse Connect Secure / Policy Secure and
// Desktop Client rows are kept, not Pulse One, vADC or the mobile clients.

const HUB_ARTICLE = 'https://hub.ivanti.com/s/article/';

/** One affected range of one product. A bound left out is open on that side. */
interface Range {
  /** Inclusive lower bound. */
  from?: string;
  /** Inclusive upper bound, when the article names the last affected version. */
  through?: string;
  /** The release that fixes it (exclusive upper bound). */
  fixed?: string;
}

interface Product {
  product: string;
  ranges: Range[];
  /** A fix that exists but is not a version (an RPM script per release). */
  patchAvailable?: boolean;
}

interface LegacyCve {
  cve: string;
  /** Absent when the article gives no score for this CVE. */
  score?: number;
  vector?: string;
  description: string;
  products: Product[];
}

interface LegacyArticle {
  /** The article's name on the hub: the last segment of its URL. */
  article: string;
  title: string;
  cves: LegacyCve[];
}

const PCS = 'Pulse Connect Secure';
const PPS = 'Pulse Policy Secure';
const ICS = 'Connect Secure';
const IPS = 'Policy Secure';
const ZTA = 'Neurons for ZTA gateways';

/** "Resolved in <release>": every earlier release of the product is affected. */
const below = (fixed: string): Range[] => [{ fixed }];

/**
 * A Connect Secure / Policy Secure / ZTA patch is a rebuild of an R-train
 * ("9.1R18.4" patches train 9.1R18; "22.2R3" is the first build of its train).
 * The affected range of a patched build is its train before it: from the start
 * of the train, or, for a first build, from the start of the line.
 */
function trainRanges(fixedBuilds: string[]): Range[] {
  return fixedBuilds.map(fixed => {
    const m = fixed.match(/^(\d+\.\d+)R(\d+)(?:\.(\d+))?$/)!;
    return { from: m[3] === undefined ? m[1] : `${m[1]}R${m[2]}`, fixed };
  });
}

export const IVANTI_LEGACY_ARTICLES: LegacyArticle[] = [
  {
    article: 'SA44101',
    title: 'SA44101 - 2019-04: Out-of-Cycle Advisory: Multiple vulnerabilities resolved in Pulse Connect Secure / Pulse Policy Secure 9.0RX',
    cves: [
      {
        cve: 'CVE-2019-11510', score: 10, vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        description: 'Unauthenticated remote attacker with network access via HTTPS can send a specially crafted URI to perform an arbitrary file reading vulnerability.',
        // For this CVE the article lists 8.1R and below as not impacted.
        products: [{
          product: PCS,
          ranges: [
            { from: '9.0R1', through: '9.0R3.3', fixed: '9.0R3.4' },
            { from: '8.3R1', through: '8.3R7', fixed: '8.3R7.1' },
            { from: '8.2R1', through: '8.2R12', fixed: '8.2R12.1' },
          ],
        }],
      },
      {
        cve: 'CVE-2019-11539', score: 8.0, vector: 'CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H',
        description: 'Authenticated attacker via the admin web interface allow attacker to inject and execute command injection',
        products: [
          {
            product: PCS,
            ranges: [
              { from: '9.0R1', through: '9.0R3.3', fixed: '9.0R3.4' },
              { from: '8.3R1', through: '8.3R7', fixed: '8.3R7.1' },
              { from: '8.2R1', through: '8.2R12', fixed: '8.2R12.1' },
              { from: '8.1R1', through: '8.1R15', fixed: '8.1R15.1' },
            ],
          },
          {
            product: PPS,
            ranges: [
              { from: '9.0R1', through: '9.0R3.1', fixed: '9.0R3.2' },
              { from: '5.4R1', through: '5.4R7', fixed: '5.4R7.1' },
              { from: '5.3R1', through: '5.3R12', fixed: '5.3R12.1' },
              { from: '5.2R1', through: '5.2R12', fixed: '5.2R12.1' },
              { from: '5.1R1', through: '5.1R15', fixed: '5.1R15.1' },
            ],
          },
        ],
      },
    ],
  },
  {
    article: 'SA44019',
    title: 'SA44019 - February 26 2019 OpenSSL Security Advisory',
    cves: [{
      cve: 'CVE-2019-1559',
      description: '0-byte record padding oracle (OpenSSL).',
      products: [
        { product: PCS, ranges: trainRanges(['9.0R6', '9.1R3']) },
        { product: PPS, ranges: trainRanges(['9.0R6', '9.1R3']) },
      ],
    }],
  },
  {
    article: 'SA44193',
    title: 'SA44193 - 2019-06: Out-of-Cycle Advisory: Multiple Linux Kernel and FreeBSD vulnerabilities',
    cves: [
      {
        cve: 'CVE-2019-11477', score: 7.5, vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        description: 'SACK Panic (Linux kernel).',
        products: [
          { product: PCS, ranges: trainRanges(['9.0R5', '9.1R3']) },
          { product: PPS, ranges: trainRanges(['9.0R5', '9.1R3']) },
        ],
      },
      {
        cve: 'CVE-2019-11478', score: 5.3, vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
        description: 'SACK Slowness or Excess Resource Usage (Linux kernel).',
        // The article names one fixed release for both products, 9.1R5 (updated April 2020).
        products: [{ product: PCS, ranges: below('9.1R5') }, { product: PPS, ranges: below('9.1R5') }],
      },
      {
        cve: 'CVE-2019-11479', score: 5.3, vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
        description: 'Excess Resource Consumption Due to Low MSS Values (Linux kernel).',
        products: [
          { product: PCS, ranges: trainRanges(['9.0R5', '9.1R3']) },
          { product: PPS, ranges: trainRanges(['9.0R5', '9.1R3']) },
        ],
      },
    ],
  },
  {
    article: 'SA44503',
    title: 'SA44503 - 2020-06: Out-of-Cycle Advisory: Pulse Secure Client TOCTOU Privilege Escalation Vulnerability (CVE-2020-13162)',
    cves: [{
      cve: 'CVE-2020-13162',
      description: 'A Pulse Secure client-side component (Windows only) lets a restricted user on an endpoint obtain administrative privilege. The gateways are not affected.',
      // Affected: 9.1R5 or below, 9.0Rx, 5.3Rx (Desktop Client) and 9.1R5 or below, 9.1Rx, 8.3Rx (Installer Service).
      products: [
        { product: 'Pulse Secure Desktop Client (Windows)', ranges: below('9.1R6') },
        { product: 'Pulse Secure Installer Service (Windows)', ranges: below('9.1R6') },
      ],
    }],
  },
  {
    article: 'SA44676',
    title: 'SA44676 - December 08 2020 OpenSSL Security Advisory',
    cves: [{
      cve: 'CVE-2020-1971', score: 4.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L',
      description: 'EDIPARTYNAME NULL pointer de-reference (OpenSSL).',
      products: [{ product: PCS, ranges: below('9.1R12') }, { product: PPS, ranges: below('9.1R12') }],
    }],
  },
  {
    article: 'SA44800',
    title: 'SA44800 - 2021-05: Out-of-Cycle Advisory: Pulse Connect Secure Buffer Overflow Vulnerability',
    cves: [{
      cve: 'CVE-2021-22908', score: 8.5, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H',
      description: 'Buffer Overflow in Windows File Resource Profiles in 9.X allows a remote authenticated user with privileges to browse SMB shares to execute arbitrary code as the root user. As of version 9.1R3, this permission is not enabled by default.',
      // Affected: PCS 9.0Rx, 9.1Rx.
      products: [{ product: PCS, ranges: below('9.1R11.5') }],
    }],
  },
  {
    article: 'SA44846',
    title: 'SA44846 - OpenSSL Security Advisory CVE-2021-23841',
    cves: [{
      // CVE-2021-23839 and CVE-2021-23841 in the same article are listed Not Vulnerable.
      cve: 'CVE-2021-23840', score: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
      description: 'Integer overflow in CipherUpdate (OpenSSL).',
      products: [{ product: PCS, ranges: below('9.1R12') }, { product: PPS, ranges: below('9.1R12') }],
    }],
  },
  {
    article: 'SA44858',
    title: 'SA44858 - 9.1R12 Security Fixes',
    cves: ([
      ['CVE-2021-22937', 9.1, 'AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', 'A vulnerability in Pulse Connect Secure before 9.1R12 could allow an authenticated administrator to perform a file write via a maliciously crafted archive uploaded in the administrator web interface.'],
      ['CVE-2021-22933', 7.6, 'AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H', 'A vulnerability in Pulse Connect Secure before 9.1R12 could allow an authenticated administrator to perform an arbitrary file delete via a maliciously crafted web request.'],
      ['CVE-2021-22934', 8.0, 'AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H', 'A vulnerability in Pulse Connect Secure before 9.1R12 could allow an authenticated administrator or compromised Pulse Connect Secure device in a load-balanced configuration to perform a buffer overflow via a malicious crafted web request.'],
      ['CVE-2021-22935', 9.1, 'AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', 'A vulnerability in Pulse Connect Secure before 9.1R12 could allow an authenticated administrator to perform command injection via an unsanitized web parameter.'],
      ['CVE-2021-22936', 8.2, 'AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N', 'A vulnerability in Pulse Connect Secure before 9.1R12 could allow a threat actor to perform a cross-site script attack against an authenticated administrator via an unsanitized web parameter.'],
      ['CVE-2021-22938', 7.9, 'AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:L', 'A vulnerability in Pulse Connect Secure before 9.1R12 could allow an authenticated administrator to perform command injection via an unsanitized web parameter in the administrator web console.'],
    ] as const).map(([cve, score, vector, description]): LegacyCve => ({
      cve, score, vector, description, products: [{ product: PCS, ranges: below('9.1R12') }],
    })),
  },
  {
    article: 'SA44899',
    title: 'SA44899 - CVE-2021-22965: A Vulnerability in Pulse Connect Secure Before 9.1R12.1',
    cves: [{
      cve: 'CVE-2021-22965', score: 5.9, vector: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H',
      description: 'A vulnerability in Pulse Connect Secure before 9.1R12.1 could allow an unauthenticated user to causes a denial of service when a malform request is sent to the device.',
      // Affected: "9.1R12 and Below"; fixed in 9.1R12.1 or 9.1R13.
      products: [{ product: PCS, ranges: [{ through: '9.1R12', fixed: '9.1R12.1' }] }],
    }],
  },
  {
    article: 'SA45520',
    title: "SA45520 - CVE's (CVE-2022-35254,CVE-2022-35258) may lead to DoS attack",
    cves: (() => {
      // Affected: Connect Secure 9.1R16.1, 22.2R1 and below; Policy Secure 9.1R16, 22.2R1 and below;
      // Neurons for ZTA gateways 22.2R1 and below. Connect Secure is the higher-scored product (7.5, the others 6.5).
      // 22.2R4 carries the fix too, but 22.2R3 already does, so only 22.2R3 bounds the 22.2 line.
      const products: Product[] = [
        { product: ICS, ranges: trainRanges(['9.1R14.3', '9.1R15.2', '9.1R16.2', '22.2R3']) },
        { product: IPS, ranges: trainRanges(['9.1R17', '22.2R3']) },
        { product: ZTA, ranges: [{ through: '22.2R1', fixed: '22.3R1' }] },
      ];
      const description = 'An unauthenticated attacker can cause a denial-of-service to Ivanti Connect Secure, Ivanti Policy Secure and Ivanti Neurons for Zero-Trust Gateway.';
      const vector = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H';
      return [
        { cve: 'CVE-2022-35254', score: 7.5, vector, description, products },
        { cve: 'CVE-2022-35258', score: 7.5, vector, description, products },
      ];
    })(),
  },
  {
    article: 'SA44516',
    title: 'SA44516 - 2020-07: Security Bulletin: Multiple Vulnerabilities Resolved in Pulse Connect Secure / Pulse Policy Secure 9.1R8',
    cves: [{
      cve: 'CVE-2020-8218', score: 7.2, vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
      description: 'Authenticated attacker via the admin web interface can crafted URI to perform an arbitrary code execution',
      // The article names no affected versions; its resolution is to upgrade to 9.1R8.
      products: [{ product: PCS, ranges: below('9.1R8') }, { product: PPS, ranges: below('9.1R8') }],
    }],
  },
  {
    article: 'SA44588',
    title: 'SA44588 - 2020-09: Out-of-Cycle Advisory: Multiple vulnerabilities resolved in Pulse Connect Secure / Pulse Policy Secure 9.1R8.2',
    cves: [{
      cve: 'CVE-2020-8243', score: 7.2, vector: 'CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
      description: 'A vulnerability in the admin web interface could allow an authenticated attacker to upload custom template to perform an arbitrary code execution.',
      // Affected: "9.1Rx or below".
      products: [{ product: PCS, ranges: below('9.1R8.2') }, { product: PPS, ranges: below('9.1R8.2') }],
    }],
  },
  {
    article: 'SA44601',
    title: 'SA44601 - 2020-10: Security Bulletin: Multiple Vulnerabilities Resolved in Pulse Connect Secure / Pulse Policy Secure / Pulse Secure Desktop Client 9.1R9',
    cves: [{
      cve: 'CVE-2020-8260', score: 7.2, vector: 'CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
      description: 'A vulnerability in the admin web interface could allow an authenticated attacker to perform an arbitrary code execution using uncontrolled gzip extraction.',
      // Affected: "9.1Rx or below".
      products: [{ product: PCS, ranges: below('9.1R9') }, { product: PPS, ranges: below('9.1R9') }],
    }],
  },
  {
    article: 'SA44784',
    title: 'SA44784 - 2021-04: Out-of-Cycle Advisory: Multiple Vulnerabilities Resolved in Pulse Connect Secure 9.1R11.4',
    cves: [
      {
        cve: 'CVE-2021-22893', score: 10, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        description: 'Multiple use after free in Pulse Connect Secure before 9.1R11.4 allows a remote unauthenticated attacker to execute arbitrary code via license services.',
        // Affected: "PCS 9.0R3/9.1R1 and Higher".
        products: [{ product: PCS, ranges: [{ from: '9.0R3', fixed: '9.1R11.4' }] }],
      },
      {
        cve: 'CVE-2021-22894', score: 9.9, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
        description: 'Buffer overflow in Pulse Connect Secure Collaboration Suite before 9.1R11.4 allows a remote authenticated users to execute arbitrary code as the root user via maliciously crafted meeting room.',
        products: [{ product: PCS, ranges: below('9.1R11.4') }],
      },
      {
        cve: 'CVE-2021-22899', score: 9.9, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
        description: 'Command Injection in Pulse Connect Secure before 9.1R11.4 allows a remote authenticated users to perform remote code execution via Windows File Resource Profiles.',
        products: [{ product: PCS, ranges: below('9.1R11.4') }],
      },
      {
        cve: 'CVE-2021-22900', score: 7.2, vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
        description: 'Multiple unrestricted uploads in Pulse Connect Secure before 9.1R11.4 allow an authenticated administrator to perform a file write via a maliciously crafted archive upload in the administrator web interface.',
        products: [{ product: PCS, ranges: below('9.1R11.4') }],
      },
    ],
  },
  {
    article: 'CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways',
    title: 'CVE-2023-46805 (Authentication Bypass) & CVE-2024-21887 (Command Injection) for Ivanti Connect Secure and Ivanti Policy Secure Gateways',
    cves: (() => {
      // "All supported versions - Version 9.x and 22.x"; the patch is listed per release train.
      const products: Product[] = [
        { product: ICS, ranges: trainRanges(['9.1R18.4', '9.1R17.3', '9.1R16.3', '9.1R15.3', '9.1R14.5', '22.6R2.2', '22.5R2.3', '22.5R1.2', '22.4R2.3', '22.4R1.1', '22.3R1.1', '22.2R3', '22.2R4.1', '22.1R6.1']) },
        { product: IPS, ranges: trainRanges(['9.1R18.4', '22.5R1.2', '9.1R17.3', '9.1R16.3', '22.2R3', '22.4R1.1', '22.6R1.1']) },
        { product: ZTA, ranges: trainRanges(['22.5R1.6', '22.6R1.5']) },
      ];
      return [
        {
          cve: 'CVE-2023-46805', score: 8.2, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
          description: 'An authentication bypass vulnerability in the web component of Ivanti ICS 9.x, 22.x and Ivanti Policy Secure allows a remote attacker to access restricted resources by bypassing control checks.',
          products,
        },
        {
          cve: 'CVE-2024-21887', score: 9.1, vector: 'AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H',
          description: 'A command injection vulnerability in web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.',
          products,
        },
      ];
    })(),
  },
  {
    article: 'CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure',
    title: 'CVE-2024-21888 Privilege Escalation for Ivanti Connect Secure and Ivanti Policy Secure',
    cves: (() => {
      // The patch is out for these releases; the rest of the supported ones were "to be patched in a staggered schedule".
      const products: Product[] = [
        { product: ICS, ranges: trainRanges(['9.1R14.4', '9.1R17.2', '9.1R18.3', '22.2R3', '22.4R2.2', '22.5R1.1', '22.5R2.2']) },
        { product: IPS, ranges: trainRanges(['22.2R3', '22.5R1.1']) },
        { product: ZTA, ranges: trainRanges(['22.6R1.3']) },
      ];
      return [
        {
          cve: 'CVE-2024-21888', score: 8.8, vector: 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
          description: 'A privilege escalation vulnerability in web component of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x) allows a user to elevate privileges to that of an administrator.',
          products,
        },
        {
          cve: 'CVE-2024-21893', score: 8.2, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
          description: 'A server-side request forgery vulnerability in the SAML component of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x) and Ivanti Neurons for ZTA allows an attacker to access certain restricted resources without authentication.',
          products,
        },
      ];
    })(),
  },
  {
    article: 'CVE-2023-38035-API-Authentication-Bypass-on-Sentry-Administrator-Interface',
    title: 'CVE-2023-38035 – API Authentication Bypass on Sentry Administrator Interface',
    cves: [{
      cve: 'CVE-2023-38035', score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      description: 'A security vulnerability in MICS Admin Portal in Ivanti MobileIron Sentry versions 9.18.0 and below, which may allow an attacker to bypass authentication controls on the administrative interface due to an insufficiently restrictive Apache HTTPD configuration.',
      // The fix is an RPM script per supported version, not a release.
      products: [{ product: 'Sentry', ranges: [{ through: '9.18.0' }], patchAvailable: true }],
    }],
  },
];

function severityOf(score: number | undefined): string | undefined {
  if (score === undefined) return undefined;
  return score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';
}

/** One advisory per (article, CVE), shaped like the ones ivanti-fetcher.ts builds from the current template. */
export function buildLegacyIvantiAdvisories(articles: LegacyArticle[] = IVANTI_LEGACY_ARTICLES): NormalizedAdvisory[] {
  return articles.flatMap(article => article.cves.map(row => ({
    externalId: `${article.article}/${row.cve}`,
    cveId: row.cve,
    summary: article.title,
    description: row.description,
    severity: severityOf(row.score),
    cvssScore: row.score,
    cvssVector: row.vector,
    url: `${HUB_ARTICLE}${article.article}`,
    affectedProducts: row.products.flatMap(p => p.ranges.map(r => ({
      vendor: IVANTI_VENDOR,
      product: p.product,
      versionStart: r.from,
      lastAffected: r.through,
      versionFixed: r.fixed,
      patchAvailable: r.fixed !== undefined || p.patchAvailable ? true : undefined,
    }))),
    rawData: { source: 'curated from the article', article: article.article, url: `${HUB_ARTICLE}${article.article}` },
  })));
}
