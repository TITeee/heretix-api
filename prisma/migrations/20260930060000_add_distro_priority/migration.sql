-- AlterTable
ALTER TABLE "OSVVulnerability" ADD COLUMN     "distroPriority" TEXT;

-- AlterTable
ALTER TABLE "OSVAffectedPackage" ADD COLUMN     "distroPriority" TEXT;

-- AlterTable
ALTER TABLE "AdvisoryVulnerability" ADD COLUMN     "distroPriority" TEXT;
