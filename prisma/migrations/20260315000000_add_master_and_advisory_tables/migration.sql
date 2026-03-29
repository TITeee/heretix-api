-- AlterTable
ALTER TABLE "NVDVulnerability" ADD COLUMN     "masterVulnId" TEXT;

-- AlterTable
ALTER TABLE "OSVVulnerability" ADD COLUMN     "masterVulnId" TEXT;

-- CreateTable
CREATE TABLE "Vulnerability" (
    "id" TEXT NOT NULL,
    "cveId" TEXT,
    "osvId" TEXT,
    "severity" TEXT,
    "cvssScore" DOUBLE PRECISION,
    "cvssVector" TEXT,
    "summary" TEXT,
    "publishedAt" TIMESTAMP(3),
    "modifiedAt" TIMESTAMP(3),
    "isKev" BOOLEAN NOT NULL DEFAULT false,
    "kevDateAdded" TIMESTAMP(3),
    "kevDueDate" TIMESTAMP(3),
    "kevProduct" TEXT,
    "kevVendor" TEXT,
    "kevShortDesc" TEXT,
    "kevRequiredAction" TEXT,
    "epssScore" DOUBLE PRECISION,
    "epssPercentile" DOUBLE PRECISION,
    "epssUpdatedAt" TIMESTAMP(3),
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Vulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdvisoryVulnerability" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "cveId" TEXT,
    "rawData" JSONB NOT NULL,
    "severity" TEXT,
    "cvssScore" DOUBLE PRECISION,
    "cvssVector" TEXT,
    "summary" TEXT,
    "description" TEXT,
    "url" TEXT,
    "workaround" TEXT,
    "solution" TEXT,
    "publishedAt" TIMESTAMP(3),
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "masterVulnId" TEXT,

    CONSTRAINT "AdvisoryVulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdvisoryAffectedProduct" (
    "id" TEXT NOT NULL,
    "advisoryId" TEXT NOT NULL,
    "vendor" TEXT NOT NULL,
    "product" TEXT NOT NULL,
    "versionStart" TEXT,
    "versionEnd" TEXT,
    "versionFixed" TEXT,
    "versionStartInt" BIGINT,
    "versionEndInt" BIGINT,
    "lastAffectedInt" BIGINT,
    "affectedVersions" TEXT[],
    "patchAvailable" BOOLEAN,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AdvisoryAffectedProduct_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Vulnerability_cveId_key" ON "Vulnerability"("cveId");

-- CreateIndex
CREATE UNIQUE INDEX "Vulnerability_osvId_key" ON "Vulnerability"("osvId");

-- CreateIndex
CREATE INDEX "Vulnerability_severity_idx" ON "Vulnerability"("severity");

-- CreateIndex
CREATE INDEX "Vulnerability_cvssScore_idx" ON "Vulnerability"("cvssScore");

-- CreateIndex
CREATE INDEX "Vulnerability_isKev_idx" ON "Vulnerability"("isKev");

-- CreateIndex
CREATE INDEX "Vulnerability_epssScore_idx" ON "Vulnerability"("epssScore");

-- CreateIndex
CREATE INDEX "Vulnerability_publishedAt_idx" ON "Vulnerability"("publishedAt");

-- CreateIndex
CREATE INDEX "AdvisoryVulnerability_cveId_idx" ON "AdvisoryVulnerability"("cveId");

-- CreateIndex
CREATE INDEX "AdvisoryVulnerability_source_idx" ON "AdvisoryVulnerability"("source");

-- CreateIndex
CREATE INDEX "AdvisoryVulnerability_severity_idx" ON "AdvisoryVulnerability"("severity");

-- CreateIndex
CREATE INDEX "AdvisoryVulnerability_publishedAt_idx" ON "AdvisoryVulnerability"("publishedAt");

-- CreateIndex
CREATE INDEX "AdvisoryVulnerability_masterVulnId_idx" ON "AdvisoryVulnerability"("masterVulnId");

-- CreateIndex
CREATE UNIQUE INDEX "AdvisoryVulnerability_source_externalId_key" ON "AdvisoryVulnerability"("source", "externalId");

-- CreateIndex
CREATE INDEX "AdvisoryAffectedProduct_vendor_product_idx" ON "AdvisoryAffectedProduct"("vendor", "product");

-- CreateIndex
CREATE INDEX "AdvisoryAffectedProduct_product_versionStartInt_versionEndI_idx" ON "AdvisoryAffectedProduct"("product", "versionStartInt", "versionEndInt");

-- CreateIndex
CREATE INDEX "AdvisoryAffectedProduct_advisoryId_idx" ON "AdvisoryAffectedProduct"("advisoryId");

-- CreateIndex
CREATE UNIQUE INDEX "NVDVulnerability_masterVulnId_key" ON "NVDVulnerability"("masterVulnId");

-- CreateIndex
CREATE INDEX "OSVVulnerability_masterVulnId_idx" ON "OSVVulnerability"("masterVulnId");

-- AddForeignKey
ALTER TABLE "OSVVulnerability" ADD CONSTRAINT "OSVVulnerability_masterVulnId_fkey" FOREIGN KEY ("masterVulnId") REFERENCES "Vulnerability"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "NVDVulnerability" ADD CONSTRAINT "NVDVulnerability_masterVulnId_fkey" FOREIGN KEY ("masterVulnId") REFERENCES "Vulnerability"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AdvisoryVulnerability" ADD CONSTRAINT "AdvisoryVulnerability_masterVulnId_fkey" FOREIGN KEY ("masterVulnId") REFERENCES "Vulnerability"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AdvisoryAffectedProduct" ADD CONSTRAINT "AdvisoryAffectedProduct_advisoryId_fkey" FOREIGN KEY ("advisoryId") REFERENCES "AdvisoryVulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;
