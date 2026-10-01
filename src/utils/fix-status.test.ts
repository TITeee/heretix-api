import { describe, it, expect } from 'vitest';
import { redHatRemediationStatus } from './fix-status.js';

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
