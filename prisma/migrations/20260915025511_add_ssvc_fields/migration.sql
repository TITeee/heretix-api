-- AlterTable
ALTER TABLE "Vulnerability" ADD COLUMN     "ssvcAutomatable" TEXT,
ADD COLUMN     "ssvcExploitation" TEXT,
ADD COLUMN     "ssvcTechnicalImpact" TEXT,
ADD COLUMN     "ssvcTimestamp" TIMESTAMP(3);
