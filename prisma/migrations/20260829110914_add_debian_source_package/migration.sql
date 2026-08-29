-- CreateTable
CREATE TABLE "DebianSourcePackage" (
    "id" TEXT NOT NULL,
    "ecosystem" TEXT NOT NULL,
    "binaryName" TEXT NOT NULL,
    "sourceName" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DebianSourcePackage_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "DebianSourcePackage_ecosystem_binaryName_idx" ON "DebianSourcePackage"("ecosystem", "binaryName");

-- CreateIndex
CREATE UNIQUE INDEX "DebianSourcePackage_ecosystem_binaryName_key" ON "DebianSourcePackage"("ecosystem", "binaryName");
