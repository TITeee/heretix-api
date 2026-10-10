-- Prefix search on names, for the name suggestions (GET /vulnerabilities/suggest).
--
-- Under any collation but "C" (a Windows or ICU/glibc locale: the default of most
-- databases), a B-tree index cannot serve LIKE 'x%', so every suggestion read a whole
-- index of millions of rows. These indexes use text_pattern_ops, which can, and are on
-- lower(name) so one lowercase pattern finds a name whatever its case.
--
-- Hand-written on purpose: Prisma's schema cannot express an expression index, and
-- leaves one alone when it compares the database with schema.prisma (unlike a
-- text_pattern_ops index on the plain column, which it reports as drift on every
-- `migrate dev`). The suggestions' queries must use the same expression, lower(...),
-- and one LIKE per pattern joined by OR (a LIKE ANY(array) cannot use these).
--
-- Each takes a few seconds per million rows and holds a write lock on its table while
-- it builds, so this runs once at the first start after the upgrade, before imports.

-- CreateIndex
CREATE INDEX "NVDAffectedPackage_lower_packageName_idx" ON "NVDAffectedPackage" (lower("packageName") text_pattern_ops);

-- CreateIndex
CREATE INDEX "NVDAffectedPackage_lower_vendor_idx" ON "NVDAffectedPackage" (lower("vendor") text_pattern_ops);

-- CreateIndex
CREATE INDEX "OSVAffectedPackage_lower_packageName_idx" ON "OSVAffectedPackage" (lower("packageName") text_pattern_ops);

-- CreateIndex
CREATE INDEX "CnaAffectedProduct_lower_product_idx" ON "CnaAffectedProduct" (lower("product") text_pattern_ops);
