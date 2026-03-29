-- CreateTable
CREATE TABLE "Vulnerability" (
    "id" TEXT NOT NULL,
    "osvId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "ecosystem" TEXT,
    "rawData" JSONB NOT NULL,
    "packageName" TEXT,
    "severity" TEXT,
    "cvssScore" DOUBLE PRECISION,
    "summary" TEXT,
    "publishedAt" TIMESTAMP(3),
    "modifiedAt" TIMESTAMP(3),
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Vulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AffectedPackage" (
    "id" TEXT NOT NULL,
    "vulnerabilityId" TEXT NOT NULL,
    "ecosystem" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,
    "versionType" TEXT NOT NULL DEFAULT 'semver',
    "introducedVersion" TEXT,
    "fixedVersion" TEXT,
    "lastAffectedVersion" TEXT,
    "introducedInt" BIGINT,
    "fixedInt" BIGINT,
    "lastAffectedInt" BIGINT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AffectedPackage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CollectionJob" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "priority" INTEGER NOT NULL DEFAULT 0,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "duration" INTEGER,
    "totalFetched" INTEGER NOT NULL DEFAULT 0,
    "totalInserted" INTEGER NOT NULL DEFAULT 0,
    "totalUpdated" INTEGER NOT NULL DEFAULT 0,
    "totalFailed" INTEGER NOT NULL DEFAULT 0,
    "errorMessage" TEXT,
    "errorStack" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CollectionJob_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Vulnerability_osvId_key" ON "Vulnerability"("osvId");

-- CreateIndex
CREATE INDEX "Vulnerability_source_ecosystem_idx" ON "Vulnerability"("source", "ecosystem");

-- CreateIndex
CREATE INDEX "Vulnerability_packageName_idx" ON "Vulnerability"("packageName");

-- CreateIndex
CREATE INDEX "Vulnerability_severity_idx" ON "Vulnerability"("severity");

-- CreateIndex
CREATE INDEX "Vulnerability_publishedAt_idx" ON "Vulnerability"("publishedAt");

-- CreateIndex
CREATE INDEX "Vulnerability_osvId_idx" ON "Vulnerability"("osvId");

-- CreateIndex
CREATE INDEX "AffectedPackage_ecosystem_packageName_idx" ON "AffectedPackage"("ecosystem", "packageName");

-- CreateIndex
CREATE INDEX "AffectedPackage_packageName_introducedInt_fixedInt_idx" ON "AffectedPackage"("packageName", "introducedInt", "fixedInt");

-- CreateIndex
CREATE INDEX "AffectedPackage_vulnerabilityId_idx" ON "AffectedPackage"("vulnerabilityId");

-- CreateIndex
CREATE INDEX "CollectionJob_source_status_idx" ON "CollectionJob"("source", "status");

-- CreateIndex
CREATE INDEX "CollectionJob_status_priority_createdAt_idx" ON "CollectionJob"("status", "priority", "createdAt");

-- CreateIndex
CREATE INDEX "CollectionJob_completedAt_idx" ON "CollectionJob"("completedAt");

-- AddForeignKey
ALTER TABLE "AffectedPackage" ADD CONSTRAINT "AffectedPackage_vulnerabilityId_fkey" FOREIGN KEY ("vulnerabilityId") REFERENCES "Vulnerability"("id") ON DELETE CASCADE ON UPDATE CASCADE;
