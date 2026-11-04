# RFAI Council MCP server container.
#
# Build context: this mcp/ folder (on Koyeb set Work directory = mcp, Dockerfile location = Dockerfile).
#   docker build -t rfai-council-mcp mcp/
#
# The image holds no secrets. Every credential (RFAI_MCP_SECRET, RFAI_MCP_OWNER_PASSCODE_HASH,
# RFAI_LLM_KEY, RFAI_TRUSTED_SIGNERS) is supplied as an environment variable at run time.
# The server keeps no files: OAuth tokens are signed, so no volume is needed.
#
# Base image: Node 24 on Alpine 3.24, pinned by digest for reproducible builds.
# To update: look up the current digest for node:24-alpine3.24 on Docker Hub and replace both lines.

FROM node:24-alpine3.24@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# Production dependencies only, exactly as locked, with install scripts disabled.
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force

FROM node:24-alpine3.24@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85
ENV NODE_ENV=production \
    PORT=8080
WORKDIR /app
# Files stay owned by root and read-only to the app user; the server never writes to disk.
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
# npm is not needed at run time; removing it shrinks the attack surface.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/healthz" || exit 1
# Node 24 runs the TypeScript sources directly (type stripping); no build step.
CMD ["node", "src/server.ts"]
