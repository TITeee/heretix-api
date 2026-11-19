-- AlterTable
ALTER TABLE "CnaAffectedProduct" ADD COLUMN     "hotfixes" TEXT[] DEFAULT ARRAY[]::TEXT[];
