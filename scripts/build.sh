#!/bin/bash
set -e

# Source shared configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
source "$SCRIPT_DIR/config.sh"

print_header "Build"

# Accept version as first argument, or use default
VERSION=${1:-0.1.0-dev}
BUILD_DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

print_info "Building with version: $VERSION"

# Always run docker build from the brick-auth root directory
cd "$SCRIPT_DIR/.."
echo "Current directory: $(pwd)"
ls -la
if [ ! -f "Dockerfile" ]; then
  echo "Error: Dockerfile not found in $(pwd)"
  exit 1
fi
IMAGE_NAME="brick-auth"
docker build --no-cache -f Dockerfile --build-arg VERSION=$VERSION --build-arg BUILD_DATETIME=$BUILD_DATETIME -t $IMAGE_NAME:$VERSION -t $IMAGE_NAME:latest .

print_info "Build completed!"
print_info "Image: $IMAGE_NAME:$VERSION"
print_info "Image: $IMAGE_NAME:latest"