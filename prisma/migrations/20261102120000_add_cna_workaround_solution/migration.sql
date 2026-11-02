-- AlterTable
ALTER TABLE "Vulnerability" ADD COLUMN     "cnaProvider" TEXT,
ADD COLUMN     "cnaSolution" TEXT,
ADD COLUMN     "cnaWorkaround" TEXT;
