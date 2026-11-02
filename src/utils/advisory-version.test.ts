import { describe, it, expect } from 'vitest';
import { VENDORS_WITH_OWN_VERSION_ORDER, OWN_VERSION_ORDER_SOURCES, PAN_VENDOR, IVANTI_VENDOR, CITRIX_VENDOR, MICROSOFT_VENDOR, SONICWALL_VENDOR, BROADCOM_VENDOR } from './advisory-version.js';
import { PanFetcher } from '../worker/pan-fetcher.js';
import { IvantiFetcher } from '../worker/ivanti-fetcher.js';
import { CitrixFetcher } from '../worker/citrix-fetcher.js';
import { MsrcFetcher } from '../worker/msrc-fetcher.js';
import { SonicWallFetcher } from '../worker/sonicwall-fetcher.js';
import { BroadcomFetcher } from '../worker/broadcom-fetcher.js';

describe('OWN_VERSION_ORDER_SOURCES', () => {
  it("names each vendor's source as its fetcher imports it", () => {
    expect(OWN_VERSION_ORDER_SOURCES).toEqual({
      [PAN_VENDOR]: new PanFetcher().source(),
      [IVANTI_VENDOR]: new IvantiFetcher().source(),
      [CITRIX_VENDOR]: new CitrixFetcher().source(),
      [MICROSOFT_VENDOR]: new MsrcFetcher().source(),
      [SONICWALL_VENDOR]: new SonicWallFetcher().source(),
      [BROADCOM_VENDOR]: new BroadcomFetcher().source(),
    });
    expect(Object.keys(OWN_VERSION_ORDER_SOURCES).sort()).toEqual([...VENDORS_WITH_OWN_VERSION_ORDER].sort());
  });
});
