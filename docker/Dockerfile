FROM node:18-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/psa-deps
COPY fixture/express-fixture/package.json fixture/express-fixture/package-lock.json* ./
RUN npm install --no-audit --no-fund \
    && chown -R node:node /opt/psa-deps

ENV NODE_PATH=/opt/psa-deps/node_modules
ENV PATH=/opt/psa-deps/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV HOME=/tmp

USER node
WORKDIR /workspace
