FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0

ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY public ./public
RUN useradd --create-home --uid 10002 portal && chown -R portal:portal /app
USER portal
EXPOSE 4100
CMD ["node", "src/server.js"]
