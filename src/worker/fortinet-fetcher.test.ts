import { describe, it, expect } from 'vitest';
import { parseCsaf, parseListingPage } from './fortinet-fetcher.js';

// Row markup as served by fortiguard.fortinet.com/psirt since 2026-08: the row
// link lives in a script at the end of the page, not on the row itself.
const CURRENT_LISTING = `
<section class="table-body">
  <div class="container-xxl">
    <div class="row" id="fwb_id_1">
      <div class="col-md-3">
        <b>FG-IR-26-167 Cron Job Injection in Remote Backup</b>
        <br>
        <b class="cve">CVE-2026-84387</b>
      </div>
    </div>
    <div class="row" id="fwb_id_2">
      <div class="col-md-3">
        <b>FG-IR-26-173 Null Pointer Dereference in Log Report</b>
      </div>
    </div>
  </div>
</section>
<script>
document.getElementById('fwb_id_1').addEventListener('click', function(event) {location.href = '/psirt/FG-IR-26-167'});
document.getElementById('fwb_id_2').addEventListener('click', function(event) {location.href = '/psirt/FG-IR-26-173'});
</script>`;

// The previous markup, with the link inline on the row.
const PREVIOUS_LISTING = `
<div class="row" onclick="location.href = '/psirt/FG-IR-23-165'">
  <div class="col-md-3">
    <b>FG-IR-23-165 Use of uninitialized resource in SSLVPN websocket</b>
  </div>
</div>`;

describe('parseListingPage', () => {
  it('reads advisory rows from the current listing markup', () => {
    expect(parseListingPage(CURRENT_LISTING)).toEqual([
      { advisoryId: 'FG-IR-26-167', title: 'Cron Job Injection in Remote Backup' },
      { advisoryId: 'FG-IR-26-173', title: 'Null Pointer Dereference in Log Report' },
    ]);
  });

  it('still reads the previous markup, since it does not depend on where the row link lives', () => {
    expect(parseListingPage(PREVIOUS_LISTING)).toEqual([
      { advisoryId: 'FG-IR-23-165', title: 'Use of uninitialized resource in SSLVPN websocket' },
    ]);
  });

  it('decodes HTML entities in the title, which the CSAF file name is built from', () => {
    const html = `<b>FG-IR-25-647 Multiple Fortinet Products&#39; FortiCloud SSO login authentication bypass</b>`;
    expect(parseListingPage(html)[0].title).toBe("Multiple Fortinet Products' FortiCloud SSO login authentication bypass");
  });

  it('returns nothing for a page past the end of the listing', () => {
    expect(parseListingPage('<section class="table-body"><div class="container-xxl"></div></section>')).toEqual([]);
  });
});

// The shape of a real CSAF file, reduced to the fields parseCsaf reads.
function csaf(
  productNames: string[],
  status: { known_affected: string[]; known_not_affected: string[] },
  remediation: string,
) {
  return {
    document: { title: 't', tracking: { id: 'FG-IR-00-000', initial_release_date: '2024-01-01T00:00:00Z' } },
    product_tree: { branches: [{ category: 'vendor', name: 'Fortinet', branches: productNames.map(name => ({ category: 'product', name })) }] },
    vulnerabilities: [{
      cve: 'CVE-2024-0001',
      product_status: status,
      remediations: [{ category: 'vendor_fix', details: remediation }],
    }],
  };
}

describe('parseCsaf with an exactly-listed affected version', () => {
  it('bounds the version by the later release of its branch named in known_not_affected', () => {
    const adv = parseCsaf(csaf(
      ['FortiOS'],
      { known_affected: ['FortiOS 7.4.1'], known_not_affected: ['FortiOS-7.4.2', 'FortiOS/ 7.2 all versions'] },
      'FortiOS 7.4: Upgrade to 7.4.2 or above\nFortiOS 7.2: Not Applicable',
    ), 'FG-IR-24-017');
    expect(adv!.affectedProducts).toEqual([
      { vendor: 'fortinet', product: 'FortiOS', versionStart: '7.4.1', versionFixed: '7.4.2', affectedVersions: ['7.4.1'], patchAvailable: true },
    ]);
  });

  it('ignores a fix on another branch and one that is not later', () => {
    const adv = parseCsaf(csaf(
      ['FortiOS'],
      { known_affected: ['FortiOS 7.4.3'], known_not_affected: ['FortiOS-7.4.2', 'FortiOS-7.6.1'] },
      '',
    ), 'FG-IR-24-018');
    expect(adv!.affectedProducts).toEqual([
      { vendor: 'fortinet', product: 'FortiOS', versionStart: undefined, versionFixed: undefined, affectedVersions: ['7.4.3'], patchAvailable: true },
    ]);
  });

  it('falls back to the remediation text when known_not_affected has no fixed release', () => {
    const adv = parseCsaf(csaf(
      ['FortiSandbox Cloud'],
      { known_affected: ['FortiSandbox Cloud 5.0.4'], known_not_affected: ['FortiSandbox Cloud/ 4.4 all versions'] },
      'FortiSandbox Cloud 4.4: Not Applicable\nFortiSandbox Cloud 5.0: Fortinet remediated this issue in 5.0.5 and hence customers do not need to perform any action.',
    ), 'FG-IR-26-096');
    expect(adv!.affectedProducts).toMatchObject([
      { product: 'FortiSandbox Cloud', versionStart: '5.0.4', versionFixed: '5.0.5' },
    ]);
  });

  it('picks the numerically lowest later release, not the lexicographically lowest', () => {
    const adv = parseCsaf(csaf(
      ['FortiOS'],
      { known_affected: ['FortiOS 7.4.1'], known_not_affected: ['FortiOS-7.4.10', 'FortiOS-7.4.2'] },
      '',
    ), 'FG-IR-24-019');
    expect(adv!.affectedProducts[0].versionFixed).toBe('7.4.2');
  });
});
