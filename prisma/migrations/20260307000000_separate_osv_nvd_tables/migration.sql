-- Rename Vulnerability → OSVVulnerability
ALTER TABLE "Vulnerability" RENAME TO "OSVVulnerability";

-- Rename AffectedPackage → OSVAffectedPackage
ALTER TABLE "AffectedPackage" RENAME TO "OSVAffectedPackage";

-- Rename constraints and indexes for OSVVulnerability
ALTER TABLE "OSVVulnerability" RENAME CONSTRAINT "Vulnerability_pkey" TO "OSVVulnerability_pkey";
ALTER INDEX "Vulnerability_osvId_key" RENAME TO "OSVVulnerability_osvId_key";
ALTER INDEX "Vulnerability_source_ecosystem_idx" RENAME TO "OSVVulnerability_source_ecosystem_idx";
ALTER INDEX "Vulnerability_packageName_idx" RENAME TO "OSVVulnerability_packageName_idx";
ALTER INDEX "Vulnerability_severity_idx" RENAME TO "OSVVulnerability_severity_idx";
ALTER INDEX "Vulnerability_publishedAt_idx" RENAME TO "OSVVulnerability_publishedAt_idx";
ALTER INDEX "Vulnerability_osvId_idx" RENAME TO "OSVVulnerability_osvId_idx";

-- Rename constraints and indexes for OSVAffectedPackage
ALTER TABLE "OSVAffectedPackage" RENAME CONSTRAINT "AffectedPackage_pkey" TO "OSVAffectedPackage_pkey";
ALTER TABLE "OSVAffectedPackage" RENAME CONSTRAINT "AffectedPackage_vulnerabilityId_fkey" TO "OSVAffectedPackage_vulnerabilityId_fkey";
ALTER INDEX "AffectedPackage_ecosystem_packageName_idx" RENAME TO "OSVAffectedPackage_ecosystem_packageName_idx";
ALTER INDEX "AffectedPackage_packageName_introducedInt_fixedInt_idx" RENAME TO "OSVAffectedPackage_packageName_introducedInt_fixedInt_idx";
ALTER INDEX "AffectedPackage_vulnerabilityId_idx" RENAME TO "OSVAffectedPackage_vulnerabilityId_idx";

-- Add new columns to OSVVulnerability
ALTER TABLE "OSVVulnerability" ADD COLUMN "cveId" TEXT;
ALTER TABLE "OSVVulnerability" ADD COLUMN "aliases" JSONB;

-- Set default value for source column (was NOT NULL without default in original)
ALTER TABLE "OSVVulnerability" ALTER COLUMN "source" SET DEFAULT 'osv';

-- Add indexes for new columns
CREATE INDEX "OSVVulnerability_cveId_idx" ON "OSVVulnerability"("cveId");

-- CreateTable NVDVulnerability
CREATE TABLE "NVDVulnerability" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'nvd',
    "rawData" JSONB NOT NULL,
    "severity" TEXT,
    "cvssScore" DOUBLE PRECISION,
    "cvssVector" TEXT,
    "summary" TEXT,
    "publishedAt" TIMESTAMP(3),
    "modifiedAt" TIMESTAMP(3),
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NVDVulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable NVDAffectedPackage
CREATE TABLE "NVDAffectedPackage" (
    "id" TEXT NOT NULL,
    "vulnerabilityId" TEXT NOT NULL,
    "cpe" TEXT,
    "vendor" TEXT,
    "packageName" TEXT NOT NULL,
    "ecosystem" TEXT,
    "versionStartIncluding" TEXT,
    "versionStartExcluding" TEXT,
    "versionEndIncluding" TEXT,
    "versionEndExcluding" TEXT,
    "introducedInt" BIGINT,
    "fixedInt" BIGINT,
    "lastAffectedInt" BIGINT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "NVDAffectedPackage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex for NVDVulnerability
CREATE UNIQUE INDEX "NVDVulnerability_cveId_key" ON "NVDVulnerability"("cveId");
CREATE INDEX "NVDVulnerability_cveId_idx" ON "NVDVulnerability"("cveId");
CREATE INDEX "NVDVulnerability_severity_idx" ON "NVDVulnerability"("severity");
CREATE INDEX "NVDVulnerability_publishedAt_idx" ON "NVDVulnerability"("publishedAt");

-- CreateIndex for NVDAffectedPackage
CREATE INDEX "NVDAffectedPackage_ecosystem_packageName_idx" ON "NVDAffectedPackage"("ecosystem", "packageName");
CREATE INDEX "NVDAffectedPackage_packageName_introducedInt_fixedInt_idx" ON "NVDAffectedPackage"("packageName", "introducedInt", "fixedInt");
CREATE INDEX "NVDAffectedPackage_vulnerabilityId_idx" ON "NVDAffectedPackage"("vulnerabilityId");

-- AddForeignKey for NVDAffectedPackage
ALTER TABLE "NVDAffectedPackage" ADD CONSTRAINT "NVDAffectedPackage_vulnerabilityId_fkey" FOREIGN KEY ("vulnerabilityId") REFERENCES "NVDVulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;
