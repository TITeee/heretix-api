#!/bin/sh
set -e

echo '{"level":"info","msg":"running database migrations","ts":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}'
./node_modules/.bin/prisma migrate deploy

echo '{"level":"info","msg":"starting server","port":"'"${PORT}"'","ts":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}'
exec node dist/index.js
