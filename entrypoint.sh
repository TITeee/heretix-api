#!/bin/sh
set -e

echo '{"level":"info","msg":"running database migrations","ts":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}'
./node_modules/.bin/prisma migrate deploy

echo '{"level":"info","msg":"running data backfill scripts","ts":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}'
node dist/scripts/migrate-all.js

# Slow backfills (migrate-background-*) run beside the server instead of holding it back.
# A failure is logged and retried on the next start; the server does not depend on it.
(node dist/scripts/migrate-all.js --background || echo '{"level":"error","msg":"background backfill failed","ts":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}') &

echo '{"level":"info","msg":"starting server","port":"'"${PORT}"'","ts":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}'
exec node dist/index.js
