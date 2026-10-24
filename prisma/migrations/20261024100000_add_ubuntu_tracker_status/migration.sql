-- CreateTable
CREATE TABLE "UbuntuTrackerStatus" (
    "id" TEXT NOT NULL,
    "ecosystem" TEXT NOT NULL,
    "sourcePackage" TEXT NOT NULL,
    "vulnId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "reason" TEXT,

    CONSTRAINT "UbuntuTrackerStatus_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "UbuntuTrackerStatus_vulnId_idx" ON "UbuntuTrackerStatus"("vulnId");

-- CreateIndex
CREATE UNIQUE INDEX "UbuntuTrackerStatus_ecosystem_sourcePackage_vulnId_key" ON "UbuntuTrackerStatus"("ecosystem", "sourcePackage", "vulnId");
