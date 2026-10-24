-- The OSV feeds of vendors that publish several ecosystems in one bucket ("Echo" holds
-- "Echo:PyPI", "Echo:Maven", ...) were one job per ecosystem ("osv-Echo:Maven"), each asking
-- for a bucket that does not exist. They are now one job per vendor ("osv-Echo"); see
-- src/jobs/osv-bucket.ts. A job with no JobConfig row is off, so without this the new jobs
-- would stay off wherever the old ones were on. The new job is on when any of the old ones was.
INSERT INTO "JobConfig" ("source", "enabled", "updatedAt")
SELECT base.source, true, NOW()
FROM (VALUES
  ('osv-Echo'), ('osv-Root'), ('osv-SUSE'), ('osv-openSUSE'), ('osv-openEuler'), ('osv-TuxCare'),
  ('osv-Mageia'), ('osv-Alpaquita'), ('osv-BellSoft Hardened Containers'), ('osv-Azure Linux'),
  ('osv-Red Hat'), ('osv-VSCode')
) AS base(source)
WHERE EXISTS (
  SELECT 1 FROM "JobConfig" old
  WHERE old."enabled" AND old."source" LIKE base.source || ':%'
)
ON CONFLICT ("source") DO NOTHING;
