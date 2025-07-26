# Build stage: Compile the Go application
FROM golang:1.21-alpine AS builder

# Build arguments for versioning
ARG VERSION=0.1.0-dev
ARG BUILD_DATETIME

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:17001/health || exit 1

# Copy go module files and download dependencies
# This leverages Docker's layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod tidy

# Copy the rest of the source code
COPY . .

# Build the applications
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags "-X 'main.AppVersion=${VERSION}' -X 'main.BuildDateTime=${BUILD_DATETIME}'" \
    -o brick-auth ./cmd/auth && \
    CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo \
    -ldflags "-X 'main.AppVersion=${VERSION}' -X 'main.BuildDateTime=${BUILD_DATETIME}'" \
    -o seeder ./cmd/seeder

# Create build-info and version files
RUN echo "${VERSION}" > /app/VERSION && \
    echo "{\"version\":\"${VERSION}\",\"buildDateTime\":\"${BUILD_DATETIME}\",\"buildTimestamp\":$(date +%s),\"environment\":\"production\",\"service\":\"brick-auth\",\"description\":\"Brick Auth Service\"}" > /app/build-info.json

# ---

# Final stage: Create the small runtime image
FROM alpine:latest

# Install only necessary runtime dependencies
RUN apk --no-cache add ca-certificates tzdata sqlite curl

# Create a non-root user and group
RUN addgroup -g 1001 -S brick && \
    adduser -u 1001 -S brick -G brick

# Create required directories
RUN mkdir -p /app /etc/brick-auth /var/log/brick-auth /var/lib/brick-auth && \
    chown -R brick:brick /app /etc/brick-auth /var/log/brick-auth /var/lib/brick-auth

# Set working directory
WORKDIR /app

# Copy compiled binaries and essential files from the builder stage
COPY --from=builder /app/brick-auth .
COPY --from=builder /app/seeder .
COPY --from=builder /app/VERSION .
COPY --from=builder /app/build-info.json .
COPY --from=builder /app/data/ ./data/
COPY --from=builder /app/private.pem .
COPY --from=builder /app/entrypoint.sh .

# Set correct ownership for copied files
RUN chown brick:brick brick-auth seeder VERSION build-info.json private.pem entrypoint.sh && \
    chown -R brick:brick ./data && \
    chmod +x entrypoint.sh

# Switch to the non-root user
USER brick

# Expose the application port
EXPOSE 17001

# Set the health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:17001/health || exit 1

# Set the entrypoint
ENTRYPOINT ["./entrypoint.sh"]