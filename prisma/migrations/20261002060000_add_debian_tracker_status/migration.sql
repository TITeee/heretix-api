-- CreateTable
CREATE TABLE "DebianTrackerStatus" (
    "id" TEXT NOT NULL,
    "ecosystem" TEXT NOT NULL,
    "sourcePackage" TEXT NOT NULL,
    "vulnId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "urgency" TEXT,
    "nodsa" TEXT,
    "nodsaReason" TEXT,

    CONSTRAINT "DebianTrackerStatus_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DebianTrackerStatus_vulnId_idx" ON "DebianTrackerStatus"("vulnId");

-- CreateIndex
CREATE UNIQUE INDEX "DebianTrackerStatus_ecosystem_sourcePackage_vulnId_key" ON "DebianTrackerStatus"("ecosystem", "sourcePackage", "vulnId");

