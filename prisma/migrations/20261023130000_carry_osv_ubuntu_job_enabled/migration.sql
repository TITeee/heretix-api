-- The OSV delta jobs for Ubuntu were one job per release ("osv-Ubuntu:22.04:LTS",
-- "osv-Ubuntu:Pro:20.04:LTS", ...) and are now one job, "osv-Ubuntu", since OSV serves all
-- releases from one shared bucket (src/jobs/osv-bucket.ts). A job with no JobConfig row is
-- off, so without this the new job would stay off in every environment that had switched the
-- old ones on. It is on when any of the old ones was, and an existing row is never changed.
INSERT INTO "JobConfig" ("source", "enabled", "updatedAt")
SELECT 'osv-Ubuntu', true, NOW()
WHERE EXISTS (
  SELECT 1 FROM "JobConfig" old
  WHERE old."enabled" AND old."source" LIKE 'osv-Ubuntu:%'
)
ON CONFLICT ("source") DO NOTHING;
