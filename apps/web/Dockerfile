# Stage 1: Build
FROM node:20-slim AS builder
WORKDIR /app
RUN npm install -g pnpm

# Copy web app configuration
COPY package.json pnpm-lock.yaml ./

# Install dependencies
RUN pnpm install

# Copy all source
COPY . .

# Build the web app
RUN pnpm build

# Stage 2: Runtime
FROM node:20-slim
WORKDIR /app
COPY --from=builder /app/build ./build
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules

EXPOSE 3000
ENV NODE_ENV=production
ENV PORT=3000
CMD ["node", "build"]
