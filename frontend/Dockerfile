# ===========================================
# PadmaVue.ai Frontend Dockerfile
# Security-hardened Next.js application
# ===========================================

# Build stage
FROM node:20-alpine AS builder

# Security: Don't run as root during build
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (using npm install to handle lock file updates)
RUN npm install --legacy-peer-deps

# Copy source code
COPY --chown=nextjs:nodejs . .

# Build the application
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ===========================================
# Production stage
# ===========================================
FROM node:20-alpine AS production

# Security: Create non-root user
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs

WORKDIR /app

# Set environment
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000

# Copy only necessary files from builder
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

# Security: Set proper ownership
RUN chown -R nextjs:nodejs /app

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Health check - use node to check if server is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000', (r) => { process.exit(r.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

# Run the application
CMD ["node", "server.js"]
