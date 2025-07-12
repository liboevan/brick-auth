#!/bin/bash
set -e

# 进入 brick-auth 目录
cd "$(dirname "$0")/.."

echo "Using Docker to generate go.sum..."

docker run --rm -v "$PWD":/go/src/app -w /go/src/app golang:1.21-alpine \
    sh -c "go mod tidy && chown $(id -u):$(id -g) go.sum"

echo "go.sum generated (or updated)!" 