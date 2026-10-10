# Known issues

Current limitations. Measured accuracy for individual products is in [ACCURACY.md](../ACCURACY.md).

## Matching

### Go sub-modules need the exact module path

OSV records Go vulnerabilities per sub-module (`go.opentelemetry.io/otel/baggage`), not per parent module (`go.opentelemetry.io/otel`). A search for the parent finds nothing when only a sub-module is affected. Search with the exact sub-module path, as dependency-graph tools do:

```
GET /api/v1/vulnerabilities/search?package=go.opentelemetry.io/otel/baggage&version=1.36.0&ecosystem=Go
```

### NVD and OSV name the same package differently

NVD uses the CPE product name, which can differ from the OSV package name (NVD `xz`, OSV `xz-utils`). The two are not normalized to each other. For NVD names, use the [suggest](api.md#package-name-autocomplete) endpoint or the [product aliases](data-sources.md#product-name-aliases).

### NVD CPE update qualifiers

Old-style CPEs that put the version detail in the `<update>` field are only partly recovered. Junos (`junos:21.2:r1-s1` is read as `21.2R1-S1`) and `update_N` / `rcN` are; these patterns are not, so their versions do not order correctly:

| Pattern | Affected products |
|---|---|
| `spN` | Windows Server service packs (~23k entries) |
| `pN` | FreeBSD/OpenBSD patches (~25k entries), treated like a `.N` patch release |

### Generic version encoding

Outside the RPM, dpkg and PAN comparators, versions are compared as integers (see [architecture.md](architecture.md#version-matching)):
- Components of 1,000 or more are clamped to 999, so for example `1.2.1500` and `1.2.1999` compare equal.
- A 4th dotted component takes the release slot (`15.1.10.7 < 15.1.10.8`, F5 BIG-IP). It is left out where it is a date or build stamp above 999 (`2.0.0.20230101`), where an earlier component above 999 is already clamped (Chrome's `120.0.6099.109` and `120.0.6200.50` compare equal), and from the 5th component on.
- Only the leading number of an RPM release is used: `2136.344.4.3` and `2136.331.7` compare equal. This does not affect `Red Hat:*` / `Oracle Linux:*` searches, which use `rpmvercmp`.
- A label attached to the number is read by what it means. Pre-release labels (`dev`, `a`, `b`, `M`, `rc`, ...) sort just below their release, in stage order (`1.2.3a1 < 1.2.3rc1 < 1.2.3`). Post-release labels (`p`, `R`, `z`, `STABLE`, `u`, ...) take the release slot (`7.4 < 7.4p1 < 7.5`). Only a dotted version of up to three parts with a 1-3 digit label number is read this way. Other shapes (`21h1`, `1.305b241111`, `v200r007c00spcb00`) keep the generic encoding. Pre-release numbers above 199 compare equal, and once a label is read, anything after the first hyphen is ignored (`7.4p1-rc2` equals `7.4p1`). Junos is the exception: `21.2R3-S9` and `12.3X48-D105` keep their service release and build (release or train in the patch slot, service release in the release slot), so `21.2R3 < 21.2R3-S1 < 21.2R3-S9 < 21.2R4`.
- Versions that cannot be encoded (dates, git hashes, build IDs; about 0.5% of stored versions) fall back to package-name matching with `approximateMatch: true`.

### Large result sets are paginated in memory

A search loads every matching row, deduplicates, then applies `limit`/`offset`. This is fine for most packages, but products with thousands of CPE entries (`openssl`, `linux_kernel`) are slower and use more memory.

## Linux distributions

### RHEL / Oracle Linux module streams

Module streams are separated using the OVAL module criterion (see [data-sources.md](data-sources.md#red-hat)). Some advisories have no such criterion. For those, only `nodejs`, `postgresql`, `httpd` and the `mysql`/`mariadb`/`php` families get a fallback lower bound. Other products that mix modular and non-modular rows (`golang`, `podman`, `libvirt`, `qemu-kvm`, ...) can still match a fix from a different stream.

### Red Hat VEX bounds use the newest stream's fix

An unfixed RHEL row, and every RHEL 10 fixed row, is bounded by the newest fix across release streams. A build fixed only in an older stream (EUS, or 10.0.Z when 10.2 also has a fix) is still reported.

### RHEL 10 fixed versions can lag

RHEL 10 fixes come from Red Hat's VEX data, which is sometimes not updated after an advisory ships. Measured in October 2026, about 0.2% of RHEL 10 (CVE, package) pairs had an older fix or no fix in VEX compared with Red Hat's CSAF advisories.

### Oracle Linux has no unfixed CVE data

Oracle's OVAL feed only lists CVEs that have a fix. Oracle publishes CSAF VEX, but without a bulk archive or a documented product ID scheme, so it is not imported. Unfixed CVEs on Oracle Linux are not reported, and Oracle Linux results carry no `fixStatus`.

### Unfixed CVEs on AlmaLinux, Rocky Linux and Alpine

Their OSV data only lists fixed vulnerabilities, so unfixed ones are not reported.

### Fix status coverage

`fixStatus` comes from Red Hat VEX and the Debian security tracker only. Debian 11 is not in the tracker's export. Ubuntu's own fix policy (`ignored`, `deferred`) is not imported.

## Vendor advisories

### Ivanti advisories are found by article name

The Ivanti fetcher takes the articles of the hub.ivanti.com sitemap whose name contains `Security-Advisory` (about 90). An advisory published under another name is not found, except for the older ones that are kept as data (see [Ivanti](data-sources.md#ivanti)). The Pulse Secure bulletins from 2018 and earlier (`SA40xxx` to `SA43xxx`, about 46) are not imported. The January 2024 patches only cover the release trains Ivanti patched; an older, unpatched train is not reported. Ivanti has no feed or API for its advisories, so a change to the site's layout can break the fetch; the job then fails rather than importing nothing.

### NetScaler bulletins are read for the ADC and Gateway line only

The NetScaler source reads the ADC / Gateway / Console bulletins of 2022 and later, found by the name of the article. Older ones (the 2019-2021 Citrix ADC and SD-WAN WANOP bulletins) and the other Citrix products are not read, so a NetScaler CVE from before 2022, or one whose bulletin is not published yet, has no NetScaler advisory. The CVE-record ranges that would cover it are not stored for NetScaler, because they read the branch and the build as one version (see [NetScaler](data-sources.md#netscaler)).

### Sophos advisories have no version ranges

Sophos detail pages expose no structured version data, so only CVE IDs and severity are imported. Version searches do not return Sophos results; look up the CVE by ID instead.

### Check Point rows without a fixed take

For `All` and `Details in SK` rows on supported release lines, the feed states no fixed take; for `Details in SK` it is only in the sk article, which is not parsed. These rows report no `fixedVersion`. Release lines that use other numbering (Harmony Endpoint `E8x.x`, SmartConsole and Quantum Spark builds) are not imported.

### Broadcom legacy advisories

Older Broadcom/VMware advisories use a table without a fixed-version column and are not parsed.

### PAN advisories with an empty product tree

Some pre-2013 Palo Alto Networks CSAF documents reference products that their own `product_tree` does not define. They have no version data and are not imported.
