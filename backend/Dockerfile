# === BACKEND DOCKERFILE ===
# Multi-stage build for Node.js backend with security optimizations

# === BUILD STAGE ===
FROM node:20-alpine AS builder

# Set working directory
WORKDIR /app

# Add security: create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S -u 1001 -G nodejs nodejs

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git \
    && rm -rf /var/cache/apk/*

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# === PRODUCTION STAGE ===
FROM node:20-alpine AS production

# Set environment variables
ENV NODE_ENV=production
ENV PORT=8080

# Install security updates and required packages
RUN apk add --no-cache \
    tini \
    dumb-init \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S -u 1001 -G nodejs nodejs

# Set working directory
WORKDIR /app

# Copy node_modules from builder stage
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules

# Copy application files
COPY --chown=nodejs:nodejs . .

# Create logs directory
RUN mkdir -p logs && chown nodejs:nodejs logs

# Remove unnecessary files
RUN rm -rf \
    .git \
    .gitignore \
    Dockerfile* \
    docker-compose* \
    README.md \
    .env.example \
    tests/ \
    coverage/ \
    .nyc_output/

# Set file permissions
RUN find . -type f -exec chmod 644 {} \; && \
    find . -type d -exec chmod 755 {} \; && \
    chmod 755 server.js

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/health || exit 1

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 8080

# Use tini as init system for proper signal handling
ENTRYPOINT ["tini", "--"]

# Start the application
CMD ["node", "server.js"]

# === METADATA ===
LABEL \
    name="turning-wheel-backend" \
    description="Secure Node.js backend for The Turning Wheel application" \
    version="1.0.0" \
    maintainer="Kyaw" \
    org.opencontainers.image.title="Turning Wheel Backend" \
    org.opencontainers.image.description="Secure Node.js backend with E2E encryption" \
    org.opencontainers.image.version="1.0.0" \
    org.opencontainers.image.vendor="The Turning Wheel" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.source="https://github.com/username/turning-wheel"
