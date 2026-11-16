# syntax=docker/dockerfile:1

# ─── Stage 1: Build ──────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

RUN corepack enable && corepack prepare pnpm@10.24.0 --activate

# Playwright's own downloaded Chromium targets glibc and isn't supported on
# Alpine (musl) -- the runner stage uses Alpine's own `chromium` package
# instead (see below), so skip this build's normally-automatic download
# entirely rather than fetch a binary that will never run.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .

RUN pnpm exec prisma generate
RUN pnpm exec tsc
RUN pnpm prune --prod

# ─── Stage 2: Production runner ──────────────────────────────────────────────
FROM node:22-alpine AS runner

RUN corepack enable && corepack prepare pnpm@10.24.0 --activate

# Broadcom/Sophos advisory scraping (src/utils/browser.ts) needs a real
# Chromium binary. Playwright's own downloadable build isn't supported on
# Alpine, so install Alpine's own chromium package and point Playwright at it
# instead (PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH below).
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont

# The Ubuntu CVE Tracker job (src/worker/ubuntu-tracker-fetcher.ts) clones the
# tracker's git repository, which has no other export.
RUN apk add --no-cache git

ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser

WORKDIR /app

RUN addgroup --system --gid 1001 nodejs && \
    adduser  --system --uid 1001 heretix

# Owned by heretix as they are copied: a chown -R of /app in a step of its own
# copies all of node_modules into another layer, 420 MB more image.
COPY --from=builder --chown=heretix:nodejs /app/node_modules     ./node_modules
COPY --from=builder --chown=heretix:nodejs /app/dist             ./dist
COPY --from=builder --chown=heretix:nodejs /app/public           ./public
COPY --from=builder --chown=heretix:nodejs /app/package.json     ./package.json
COPY --from=builder --chown=heretix:nodejs /app/pnpm-lock.yaml   ./pnpm-lock.yaml
COPY --from=builder --chown=heretix:nodejs /app/.npmrc           ./.npmrc
COPY --from=builder --chown=heretix:nodejs /app/prisma           ./prisma
COPY --from=builder --chown=heretix:nodejs /app/prisma.config.ts ./prisma.config.ts

COPY --chown=heretix:nodejs --chmod=755 entrypoint.sh ./entrypoint.sh
# /app itself, which the copies above leave to root.
RUN chown heretix:nodejs /app

USER heretix

ENV NODE_ENV=production
ENV PORT=5000

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
