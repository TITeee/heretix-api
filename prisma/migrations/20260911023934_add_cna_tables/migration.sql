-- CreateTable
CREATE TABLE "CnaVulnerability" (
    "id" TEXT NOT NULL,
    "cveId" TEXT NOT NULL,
    "cnaShortName" TEXT NOT NULL,
    "datePublished" TIMESTAMP(3),
    "dateUpdated" TIMESTAMP(3),
    "rawAffected" JSONB NOT NULL,
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "masterVulnId" TEXT,

    CONSTRAINT "CnaVulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CnaAffectedProduct" (
    "id" TEXT NOT NULL,
    "vulnerabilityId" TEXT NOT NULL,
    "vendor" TEXT NOT NULL,
    "product" TEXT NOT NULL,
    "packageName" TEXT,
    "versionType" TEXT,
    "versionStart" TEXT,
    "versionEnd" TEXT,
    "lastAffected" TEXT,
    "versionStartInt" BIGINT,
    "versionEndInt" BIGINT,
    "lastAffectedInt" BIGINT,
    "affectedVersions" TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CnaAffectedProduct_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "CnaVulnerability_cveId_key" ON "CnaVulnerability"("cveId");

-- CreateIndex
CREATE UNIQUE INDEX "CnaVulnerability_masterVulnId_key" ON "CnaVulnerability"("masterVulnId");

-- CreateIndex
CREATE INDEX "CnaVulnerability_cnaShortName_idx" ON "CnaVulnerability"("cnaShortName");

-- CreateIndex
CREATE INDEX "CnaVulnerability_dateUpdated_idx" ON "CnaVulnerability"("dateUpdated");

-- CreateIndex
CREATE INDEX "CnaAffectedProduct_vendor_product_idx" ON "CnaAffectedProduct"("vendor", "product");

-- CreateIndex
CREATE INDEX "CnaAffectedProduct_product_versionStartInt_versionEndInt_idx" ON "CnaAffectedProduct"("product", "versionStartInt", "versionEndInt");

-- CreateIndex
CREATE INDEX "CnaAffectedProduct_vulnerabilityId_idx" ON "CnaAffectedProduct"("vulnerabilityId");

-- AddForeignKey
ALTER TABLE "CnaVulnerability" ADD CONSTRAINT "CnaVulnerability_masterVulnId_fkey" FOREIGN KEY ("masterVulnId") REFERENCES "Vulnerability"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CnaAffectedProduct" ADD CONSTRAINT "CnaAffectedProduct_vulnerabilityId_fkey" FOREIGN KEY ("vulnerabilityId") REFERENCES "CnaVulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;
