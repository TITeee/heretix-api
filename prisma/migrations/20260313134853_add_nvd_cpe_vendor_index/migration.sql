-- CreateIndex
CREATE INDEX "NVDAffectedPackage_vendor_packageName_idx" ON "NVDAffectedPackage"("vendor", "packageName");

-- CreateIndex
CREATE INDEX "NVDAffectedPackage_cpe_idx" ON "NVDAffectedPackage"("cpe");
