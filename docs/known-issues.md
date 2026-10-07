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

Old-style CPEs that put the version detail in the `<update>` field are only partly recovered. These patterns are not, so their versions do not order correctly:

| Pattern | Affected products |
|---|---|
| `rN` / `rN-sN` | Juniper Junos (~63k entries) |
| `spN` | Windows Server service packs (~23k entries) |
| `pN` | FreeBSD/OpenBSD patches (~25k entries), treated like a `.N` patch release |

### Generic version encoding

Outside the RPM, dpkg and PAN comparators, versions are compared as integers (see [architecture.md](architecture.md#version-matching)):
- Components of 1,000 or more are clamped to 999, so for example `1.2.1500` and `1.2.1999` compare equal.
- Only the leading number of an RPM release is used: `2136.344.4.3` and `2136.331.7` compare equal. This does not affect `Red Hat:*` / `Oracle Linux:*` searches, which use `rpmvercmp`.
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

### Sophos advisories have no version ranges

Sophos detail pages expose no structured version data, so only CVE IDs and severity are imported. Version searches do not return Sophos results; look up the CVE by ID instead.

### Check Point rows without a fixed take

For `All` and `Details in SK` rows on supported release lines, the feed states no fixed take; for `Details in SK` it is only in the sk article, which is not parsed. These rows report no `fixedVersion`. Release lines that use other numbering (Harmony Endpoint `E8x.x`, SmartConsole and Quantum Spark builds) are not imported.

### Broadcom legacy advisories

Older Broadcom/VMware advisories use a table without a fixed-version column and are not parsed.

### PAN advisories with an empty product tree

Some pre-2013 Palo Alto Networks CSAF documents reference products that their own `product_tree` does not define. They have no version data and are not imported.
