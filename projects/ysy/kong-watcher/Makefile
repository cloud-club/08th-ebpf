# Kong Gateway eBPF Monitor Makefile
# Docker buildx를 활용한 멀티 아키텍처 빌드 및 푸시

# 변수 설정
IMG ?= harbor.ops.action.cloudz.co.kr/apim/kong-watcher:0.0.1
VERSION ?= 1.0.0
COMMIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

.PHONY: build push buildx clean help

# 기본 타겟
all: buildx

# Docker 이미지 빌드 (로컬)
build:
	@echo "🏗️  Building Docker image..."
	docker build \
		--build-arg BUILDPLATFORM=linux/amd64 \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH=amd64 \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT_SHA=$(COMMIT_SHA) \
		-t $(IMG) \
		.

# Docker 이미지 푸시
push:
	@echo "📤 Pushing Docker image..."
	docker push $(IMG)

# Docker buildx를 활용한 멀티 아키텍처 빌드 및 푸시
buildx:
	@echo "🚀 Building and pushing multi-architecture image..."
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg BUILDPLATFORM=linux/amd64 \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH=amd64 \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT_SHA=$(COMMIT_SHA) \
		--tag $(IMG) \
		--push \
		.

# 정리
clean:
	@echo "🧹 Cleaning up..."
	docker rmi $(IMG) 2>/dev/null || true

# 도움말
help:
	@echo "Kong Gateway eBPF Monitor - Docker Build"
	@echo ""
	@echo "Available targets:"
	@echo "  build     - Build Docker image locally"
	@echo "  push      - Push Docker image to registry"
	@echo "  buildx    - Build and push multi-architecture image (default)"
	@echo "  clean     - Clean up local Docker images"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  IMG       - Docker image name (default: $(IMG))"
	@echo "  VERSION   - Version tag (default: $(VERSION))"
	@echo "  COMMIT_SHA - Git commit SHA (default: $(COMMIT_SHA))"
	@echo ""
	@echo "Examples:"
	@echo "  make buildx"
	@echo "  make buildx IMG=my-registry.com/kong-watcher:v1.0.0"
	@echo "  make buildx VERSION=2.0.0"