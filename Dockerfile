# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

# Build arguments for version
ARG VERSION=0.1.0-dev
ARG BUILD_DATETIME
ENV VERSION=$VERSION
ENV BUILD_DATETIME=$BUILD_DATETIME

# Build the Go application with version and build datetime injected
RUN apk add --no-cache gcc musl-dev sqlite-dev \
    && export CGO_ENABLED=1 \
    && go mod tidy \
    && go build -ldflags "-X 'main.AppVersion=$VERSION' -X 'main.BuildDateTime=$BUILD_DATETIME'" -o brick-auth main.go

# Create VERSION file from build argument
RUN echo "$VERSION" > /app/VERSION

# Create build-info.json from build arguments
RUN echo "{\"version\":\"$VERSION\",\"buildDateTime\":\"$BUILD_DATETIME\",\"buildTimestamp\":$(date +%s),\"environment\":\"production\",\"service\":\"brick-auth\",\"description\":\"Brick Auth Service\"}" > /app/build-info.json

# Runtime stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/brick-auth .
COPY --from=builder /app/go.mod .
COPY --from=builder /app/VERSION .
COPY --from=builder /app/build-info.json .
COPY private_rsa_pkcs1.pem /app/private.pem
RUN apk add --no-cache sqlite-libs
EXPOSE 18001
ENTRYPOINT ["/app/brick-auth"] 