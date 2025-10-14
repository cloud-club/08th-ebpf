# Kong Gateway eBPF Monitor - Kubernetes용 Dockerfile
# Linux 환경에서 빌드 가능하도록 최적화

# 빌드 스테이지
FROM golang:1.23-alpine AS builder

# 빌드 인수 설정
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG BUILDPLATFORM

# Go 환경 변수 설정
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
ENV CGO_ENABLED=1
ENV GO111MODULE=on
ENV GOPROXY=direct
ENV GOSUMDB=off

# eBPF 빌드를 위한 필수 패키지 설치
RUN apk add --no-cache \
    clang \
    llvm \
    linux-headers \
    make \
    git \
    ca-certificates \
    build-base \
    musl-dev \
    libbpf-dev \
    zlib-dev \
    elfutils-dev \
    libelf-dev

# 작업 디렉토리 설정
WORKDIR /app

# Go 모듈 파일 복사 및 의존성 다운로드
COPY go.mod go.sum ./
RUN go mod download

# 소스 코드 복사
COPY . .

# eBPF 헤더 파일 확인
RUN ls -la headers/ || echo "Headers directory not found"

# eBPF 코드 생성 (Linux amd64 전용)
RUN echo "Generating eBPF code for ${TARGETOS}/${TARGETARCH}..." && \
    GOOS=linux GOARCH=amd64 go generate ./... && \
    echo "eBPF code generation completed"

# Go 애플리케이션 빌드
RUN echo "Building Go application..." && \
    go build -ldflags="-s -w" -o kong-watcher *.go && \
    echo "Build completed successfully"

# 빌드 결과 확인
RUN ls -la kong-watcher && file kong-watcher

# 실행 스테이지 - 최소한의 보안 이미지
FROM alpine:3.19

# eBPF 실행을 위한 필수 패키지 설치
RUN apk add --no-cache \
    ca-certificates \
    libc6-compat \
    && rm -rf /var/cache/apk/*

# 작업 디렉토리 설정
WORKDIR /app

# 빌드된 바이너리 복사
COPY --from=builder /app/kong-watcher .

# 바이너리 권한 설정
RUN chmod +x /app/kong-watcher

# 비root 사용자 생성 (보안상 권장)
RUN addgroup -g 1001 -S kong-watcher && \
    adduser -u 1001 -S kong-watcher -G kong-watcher

# 사용자 변경 (Kubernetes에서 privileged 모드로 실행되므로 root 사용 가능)
# USER kong-watcher:kong-watcher

# 헬스체크 추가
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep kong-watcher || exit 1

# 실행 명령
ENTRYPOINT ["/app/kong-watcher"]

# 메타데이터
LABEL maintainer="Kong eBPF Monitor Team"
LABEL description="Kong Gateway eBPF Monitor for Kubernetes"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/your-org/kong-watcher"
