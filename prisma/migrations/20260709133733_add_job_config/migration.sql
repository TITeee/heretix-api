-- CreateTable
CREATE TABLE "JobConfig" (
    "source" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "JobConfig_pkey" PRIMARY KEY ("source")
);
