import { describe, it, expect } from 'vitest';
import { parseListingPage } from './fortinet-fetcher.js';

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
