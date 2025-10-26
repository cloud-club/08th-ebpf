# Kong Gateway eBPF Monitor - Linux 전용 Dockerfile
# Linux 환경에서만 빌드 및 실행 가능 (eBPF는 Linux 커널 전용)

# 빌드 스테이지
FROM golang:1.23-alpine AS builder

# 빌드 인수 설정
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG BUILDPLATFORM
ARG VERSION=1.0.0
ARG COMMIT_SHA=unknown

# Go 환경 변수 설정
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
ENV CGO_ENABLED=1
ENV GO111MODULE=on
ENV GOPROXY=direct
ENV GOSUMDB=off
ENV BPF_CFLAGS="-O2 -g -Wall -Werror"

# eBPF 빌드를 위한 필수 패키지 설치 (Alpine Linux)
RUN apk add --no-cache \
    clang \
    llvm \
    linux-headers \
    make \
    git \
    ca-certificates \
    build-base \
    musl-dev \
    zlib-dev \
    elfutils-dev \
    && rm -rf /var/cache/apk/*

# 작업 디렉토리 설정
WORKDIR /app

# Go 모듈 파일 복사 및 의존성 다운로드
COPY go.mod go.sum ./
RUN go mod download

# 소스 코드 복사
COPY . .

# eBPF 헤더 파일 확인
RUN echo "=== eBPF Headers Check ===" && \
    ls -la headers/ && \
    echo "=== Headers content preview ===" && \
    head -10 headers/vmlinux.h

# eBPF 코드 생성 및 빌드 (Linux amd64 전용)
RUN echo "=== Generating eBPF code for ${TARGETOS}/${TARGETARCH} ===" && \
    GOOS=linux GOARCH=amd64 go generate ./... && \
    echo "=== eBPF code generation completed ===" && \
    ls -la *.go

# Go 애플리케이션 빌드
RUN echo "=== Building Go application ===" && \
    go build \
        -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT_SHA}" \
        -o kong-watcher \
        *.go && \
    echo "=== Build completed successfully ==="

# 빌드 결과 확인
RUN echo "=== Build verification ===" && \
    ls -la kong-watcher && \
    file kong-watcher && \
    echo "=== Binary info ===" && \
    ldd kong-watcher || echo "Static binary or ldd not available"

# 실행 스테이지 - 사이드카 컨테이너용 최적화
FROM alpine:3.19

# 메타데이터 라벨
LABEL maintainer="Kong eBPF Monitor Team" \
      description="Kong Gateway eBPF Monitor Sidecar Container" \
      version="${VERSION}" \
      org.opencontainers.image.title="kong-gateway-ebpf-monitor" \
      org.opencontainers.image.description="eBPF-based Kong Gateway traffic monitoring sidecar" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/your-org/kong-watcher" \
      org.opencontainers.image.os="linux" \
      org.opencontainers.image.arch="amd64"

# 사이드카 실행을 위한 필수 패키지 설치
RUN apk add --no-cache \
    ca-certificates \
    libc6-compat \
    procps \
    && rm -rf /var/cache/apk/*

# 작업 디렉토리 설정
WORKDIR /app

# 빌드된 바이너리 복사
COPY --from=builder /app/kong-watcher .

# 바이너리 권한 설정
RUN chmod +x /app/kong-watcher

# 사이드카 컨테이너용 사용자 생성
RUN addgroup -g 1001 -S kong-monitor && \
    adduser -u 1001 -S kong-monitor -G kong-monitor

# 사이드카 컨테이너는 privileged 모드로 실행되므로 root 사용
# USER kong-monitor:kong-monitor

# 사이드카 컨테이너용 헬스체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep kong-watcher > /dev/null || exit 1

# 사이드카 컨테이너용 환경 변수 설정
ENV LOG_LEVEL=info \
    ENABLE_JSON_LOG=false \
    STATS_INTERVAL=30s \
    KONG_PROCESS_NAME=kong

# 실행 명령
ENTRYPOINT ["/app/kong-watcher"]