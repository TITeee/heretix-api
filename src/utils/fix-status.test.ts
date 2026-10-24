import { describe, it, expect } from 'vitest';
import { debianTrackerStatus, redHatRemediationStatus, ubuntuTrackerStatus } from './fix-status.js';

describe('debianTrackerStatus', () => {
  // Real tag combinations from the tracker export.
  it.each([
    [{ status: 'open', urgency: 'not yet assigned', nodsa: 'Minor issue', nodsaReason: 'ignored' }, 'will_not_fix', 'ignored: Minor issue'],
    [{ status: 'open', urgency: 'not yet assigned', nodsa: 'Revisit when fixed upstream', nodsaReason: 'postponed' }, 'deferred', 'postponed: Revisit when fixed upstream'],
    [{ status: 'open', urgency: 'not yet assigned', nodsa: 'Minor issue', nodsaReason: '' }, 'deferred', 'no-dsa: Minor issue'],
    [{ status: 'open', urgency: 'end-of-life', nodsa: null, nodsaReason: null }, 'out_of_support', 'end-of-life'],
    [{ status: 'undetermined', urgency: 'not yet assigned' }, 'under_investigation', 'undetermined'],
    [{ status: 'open', urgency: 'unimportant', nodsa: null, nodsaReason: null }, 'affected', null],
  ])('%j -> %s', (entry, fixStatus, fixStatusDetail) => {
    expect(debianTrackerStatus(entry)).toEqual({ fixStatus, fixStatusDetail });
  });

  it('puts end-of-life ahead of a no-dsa tag on the same entry', () => {
    expect(debianTrackerStatus({ status: 'open', urgency: 'end-of-life', nodsa: 'Minor issue', nodsaReason: 'ignored' })?.fixStatus)
      .toBe('out_of_support');
  });

  it('returns null for a resolved entry -- the fix is the row\'s own fixedVersion', () => {
    expect(debianTrackerStatus({ status: 'resolved', urgency: 'low' })).toBeNull();
  });
});

describe('redHatRemediationStatus', () => {
  // The four (category, details) pairs observed on the live Red Hat VEX archive.
  it.each([
    ['no_fix_planned', 'Will not fix', 'will_not_fix'],
    ['no_fix_planned', 'Out of support scope', 'out_of_support'],
    ['none_available', 'Fix deferred', 'deferred'],
    ['none_available', 'Affected', 'affected'],
  ])('%s / %s -> %s, keeping the wording', (category, details, expected) => {
    expect(redHatRemediationStatus(category, details)).toEqual({ fixStatus: expected, fixStatusDetail: details });
  });

  it('falls back on the category for wording it does not know', () => {
    expect(redHatRemediationStatus('no_fix_planned', 'Something new')).toEqual({ fixStatus: 'will_not_fix', fixStatusDetail: 'Something new' });
    expect(redHatRemediationStatus('none_available', undefined)).toEqual({ fixStatus: 'affected', fixStatusDetail: null });
  });

  it('ignores categories that do not describe a missing fix', () => {
    expect(redHatRemediationStatus('vendor_fix', 'For details on how to apply this update...')).toBeNull();
    expect(redHatRemediationStatus('workaround', 'Do not process untrusted files.')).toBeNull();
  });
});

describe('ubuntuTrackerStatus', () => {
  it('maps each Ubuntu CVE Tracker status that means "no fix yet"', () => {
    expect(ubuntuTrackerStatus({ status: 'needs-triage' })).toEqual({ fixStatus: 'under_investigation', fixStatusDetail: 'needs-triage' });
    expect(ubuntuTrackerStatus({ status: 'needed' })).toEqual({ fixStatus: 'affected', fixStatusDetail: null });
    expect(ubuntuTrackerStatus({ status: 'pending', reason: '5.40.1-6ubuntu0.1' })).toEqual({ fixStatus: 'affected', fixStatusDetail: 'pending: 5.40.1-6ubuntu0.1' });
    expect(ubuntuTrackerStatus({ status: 'deferred', reason: '2026-10-15' })).toEqual({ fixStatus: 'deferred', fixStatusDetail: 'deferred: 2026-10-15' });
  });

  it('tells a decision not to fix from the end of support', () => {
    expect(ubuntuTrackerStatus({ status: 'ignored', reason: 'see notes' })).toEqual({ fixStatus: 'will_not_fix', fixStatusDetail: 'ignored: see notes' });
    expect(ubuntuTrackerStatus({ status: 'ignored', reason: 'only affects Perl for Windows' })?.fixStatus).toBe('will_not_fix');
    expect(ubuntuTrackerStatus({ status: 'ignored' })).toEqual({ fixStatus: 'will_not_fix', fixStatusDetail: 'ignored' });
    expect(ubuntuTrackerStatus({ status: 'ignored', reason: 'end of standard support, was deferred' })?.fixStatus).toBe('out_of_support');
    expect(ubuntuTrackerStatus({ status: 'ignored', reason: 'end of ESM support' })?.fixStatus).toBe('out_of_support');
  });

  it('has nothing to say about a status that has a fix or no problem', () => {
    for (const status of ['released', 'not-affected', 'DNE', '']) expect(ubuntuTrackerStatus({ status })).toBeNull();
  });
});
