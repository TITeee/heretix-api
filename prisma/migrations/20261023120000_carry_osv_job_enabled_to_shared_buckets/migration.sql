-- The OSV delta jobs for Debian and Alpine were one job per release ("osv-Debian:12",
-- "osv-Alpine:v3.20", ...) and are now one job per distro ("osv-Debian", "osv-Alpine"),
-- since OSV serves all releases from one shared bucket (src/jobs/osv-bucket.ts). A job with
-- no JobConfig row is off, so without this the new jobs would stay off in every environment
-- that had switched the old ones on. The new job is on when any of the old ones was.
INSERT INTO "JobConfig" ("source", "enabled", "updatedAt")
SELECT base.source, true, NOW()
FROM (VALUES ('osv-Debian'), ('osv-Alpine')) AS base(source)
WHERE EXISTS (
  SELECT 1 FROM "JobConfig" old
  WHERE old."enabled" AND old."source" LIKE base.source || ':%'
)
ON CONFLICT ("source") DO NOTHING;
