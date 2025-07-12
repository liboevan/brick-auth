# Build stage
FROM golang:1.21-alpine AS builder

# Build arguments for version
ARG VERSION=0.1.0-dev
ARG BUILD_DATETIME
ENV VERSION=$VERSION
ENV BUILD_DATETIME=$BUILD_DATETIME

# Change the apk repositories due to network restriction
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod ./

# Download dependencies and generate go.sum
RUN go mod download && go mod tidy

# Copy source code
COPY . .

# Build the application with version and build datetime injected
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags "-X 'main.AppVersion=$VERSION' -X 'main.BuildDateTime=$BUILD_DATETIME'" \
    -o brick-auth . && \
    echo "$VERSION" > /app/VERSION && \
    echo "{\"version\":\"$VERSION\",\"buildDateTime\":\"$BUILD_DATETIME\",\"buildTimestamp\":$(date +%s),\"environment\":\"production\",\"service\":\"brick-auth\",\"description\":\"Brick Auth Service\"}" > /app/build-info.json && \
    go mod verify

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata sqlite

# Create non-root user
RUN addgroup -g 1001 -S brick && \
    adduser -u 1001 -S brick -G brick

# Create necessary directories with proper permissions
RUN mkdir -p /app && \
    mkdir -p /etc/brick-auth && \
    mkdir -p /var/log/brick-auth && \
    mkdir -p /var/lib/brick-auth && \
    chown -R brick:brick /app && \
    chown -R brick:brick /etc/brick-auth && \
    chown -R brick:brick /var/log/brick-auth && \
    chown -R brick:brick /var/lib/brick-auth

# Copy binary and build info from builder stage
COPY --from=builder /app/brick-auth /app/
COPY --from=builder /app/VERSION /app/
COPY --from=builder /app/build-info.json /app/

# Copy private key
COPY private.pem /app/private.pem

# Set ownership of the binary and build info files
RUN chown brick:brick /app/brick-auth && \
    chown brick:brick /app/VERSION && \
    chown brick:brick /app/build-info.json && \
    chown brick:brick /app/private.pem

# Switch to non-root user
USER brick

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 17001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:17001/health || exit 1

# Run the application
CMD ["./brick-auth"] 