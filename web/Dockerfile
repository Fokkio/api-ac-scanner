FROM node:20-slim

WORKDIR /app

# Install all deps (dev needed for tsc build), then prune after build
COPY package.json package-lock.json* ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src
COPY views ./views
COPY public ./public

RUN npm run build

# Prune dev dependencies for a smaller runtime image
RUN npm prune --omit=dev

# Non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 3000

CMD ["node", "dist/server.js"]
