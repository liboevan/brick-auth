# Build stage
FROM golang:1.21-alpine AS builder

# Build arguments for version
ARG VERSION=0.1.0-dev
ARG BUILD_DATETIME
ENV VERSION=$VERSION
ENV BUILD_DATETIME=$BUILD_DATETIME

# Change the apk repositories and install build dependencies
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache git ca-certificates tzdata gcc musl-dev sqlite-dev

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
    -o brick-auth ./cmd/auth && \
    CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags "-X 'main.AppVersion=$VERSION' -X 'main.BuildDateTime=$BUILD_DATETIME'" \
    -o seeder ./cmd/seeder && \
    echo "$VERSION" > /app/VERSION && \
    echo "{\"version\":\"$VERSION\",\"buildDateTime\":\"$BUILD_DATETIME\",\"buildTimestamp\":$(date +%s),\"environment\":\"production\",\"service\":\"brick-auth\",\"description\":\"Brick Auth Service\"}" > /app/build-info.json && \
    go mod verify

# Final stage
FROM alpine:latest

# Install runtime dependencies, create user, and set up directories
RUN apk --no-cache add ca-certificates tzdata sqlite && \
    addgroup -g 1001 -S brick && \
    adduser -u 1001 -S brick -G brick && \
    mkdir -p /app /etc/brick-auth /var/log/brick-auth /var/lib/brick-auth && \
    chown -R brick:brick /app /etc/brick-auth /var/log/brick-auth /var/lib/brick-auth

# Copy binaries and build info from builder stage
COPY --from=builder /app/brick-auth /app/
COPY --from=builder /app/seeder /app/
COPY --from=builder /app/VERSION /app/
COPY --from=builder /app/build-info.json /app/

# Copy data files
COPY data/ /app/data/

# Copy private key
COPY private.pem /app/private.pem

# Set ownership of all copied files
RUN chown brick:brick /app/brick-auth /app/seeder /app/VERSION /app/build-info.json /app/private.pem && \
    chown -R brick:brick /app/data

# Copy and set up entrypoint script
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && \
    chown brick:brick /app/entrypoint.sh

# Switch to non-root user
USER brick

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 17001

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:17001/health || exit 1

# Run the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"] 