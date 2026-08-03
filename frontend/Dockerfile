# === FRONTEND DOCKERFILE ===
# Multi-stage build for React frontend with security optimizations

# === BUILD STAGE ===
FROM node:20-alpine AS builder

# Set working directory
WORKDIR /app

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
RUN npm ci

# Copy source code
COPY . .

# Build arguments for environment configuration
ARG VITE_API_URL
ARG VITE_APP_NAME="The Turning Wheel"
ARG VITE_APP_VERSION="1.0.0"

# Set environment variables for build
ENV VITE_API_URL=${VITE_API_URL}
ENV VITE_APP_NAME=${VITE_APP_NAME}
ENV VITE_APP_VERSION=${VITE_APP_VERSION}
ENV NODE_ENV=production

# Build the application
RUN npm run build

# === NGINX STAGE ===
FROM nginx:1.25-alpine AS production

# Install security updates
RUN apk add --no-cache \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user for nginx
RUN addgroup -g 1001 -S nginx-user && \
    adduser -S -u 1001 -G nginx-user nginx-user

# Copy built application from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY nginx-site.conf /etc/nginx/conf.d/default.conf

# Create nginx cache and logs directories with proper permissions
RUN mkdir -p /var/cache/nginx /var/log/nginx /var/run && \
    chown -R nginx-user:nginx-user /var/cache/nginx /var/log/nginx /var/run /usr/share/nginx/html && \
    chmod -R 755 /var/cache/nginx /var/log/nginx /var/run

# Create nginx pid directory
RUN mkdir -p /tmp/nginx && \
    chown nginx-user:nginx-user /tmp/nginx

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Switch to non-root user
USER nginx-user

# Expose port
EXPOSE 3000

# Start nginx
CMD ["nginx", "-g", "daemon off;"]

# === METADATA ===
LABEL \
    name="turning-wheel-frontend" \
    description="React frontend for The Turning Wheel application" \
    version="1.0.0" \
    maintainer="Kyaw" \
    org.opencontainers.image.title="Turning Wheel Frontend" \
    org.opencontainers.image.description="React frontend with WebCrypto E2E encryption" \
    org.opencontainers.image.version="1.0.0" \
    org.opencontainers.image.vendor="The Turning Wheel" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.source="https://github.com/username/turning-wheel"
