#!/bin/bash

# Kong Gateway eBPF Monitor - Kubernetes 빌드 스크립트
# Linux 환경에서 실행해야 함

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 로그 함수
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 환경 변수 설정
IMAGE_NAME=${IMAGE_NAME:-"harbor.ops.action.cloudz.co.kr/apim/kong-watcher"}
IMAGE_TAG=${IMAGE_TAG:-"0.0.2"}
BUILD_PLATFORM=${BUILD_PLATFORM:-"linux/amd64"}
DOCKERFILE=${DOCKERFILE:-"Dockerfile"}

# 필수 도구 확인
check_requirements() {
    log_info "필수 도구 확인 중..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker가 설치되어 있지 않습니다."
        exit 1
    fi
    
    if ! command -v go &> /dev/null; then
        log_error "Go가 설치되어 있지 않습니다."
        exit 1
    fi
    
    if ! command -v clang &> /dev/null; then
        log_error "Clang이 설치되어 있지 않습니다."
        exit 1
    fi
    
    log_success "모든 필수 도구가 설치되어 있습니다."
}

# Go 모듈 확인
check_go_modules() {
    log_info "Go 모듈 확인 중..."
    
    if [ ! -f "go.mod" ]; then
        log_error "go.mod 파일이 없습니다."
        exit 1
    fi
    
    if [ ! -f "go.sum" ]; then
        log_warning "go.sum 파일이 없습니다. go mod tidy를 실행합니다."
        go mod tidy
    fi
    
    log_success "Go 모듈 확인 완료"
}

# eBPF 헤더 파일 확인
check_ebpf_headers() {
    log_info "eBPF 헤더 파일 확인 중..."
    
    if [ ! -d "headers" ]; then
        log_warning "headers 디렉토리가 없습니다. 생성합니다."
        mkdir -p headers
    fi
    
    if [ ! -f "headers/vmlinux.h" ]; then
        log_warning "vmlinux.h 파일이 없습니다."
        log_info "vmlinux.h를 생성하려면 다음 명령을 실행하세요:"
        log_info "bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h"
    fi
    
    log_success "eBPF 헤더 파일 확인 완료"
}

# Docker 이미지 빌드
build_image() {
    log_info "Docker 이미지 빌드 시작..."
    log_info "이미지: ${IMAGE_NAME}:${IMAGE_TAG}"
    log_info "플랫폼: ${BUILD_PLATFORM}"
    log_info "Dockerfile: ${DOCKERFILE}"
    
    # Docker 빌드 명령
    docker build \
        --platform ${BUILD_PLATFORM} \
        --build-arg TARGETOS=linux \
        --build-arg TARGETARCH=amd64 \
        --build-arg BUILDPLATFORM=${BUILD_PLATFORM} \
        -f ${DOCKERFILE} \
        -t ${IMAGE_NAME}:${IMAGE_TAG} \
        -t ${IMAGE_NAME}:latest \
        .
    
    if [ $? -eq 0 ]; then
        log_success "Docker 이미지 빌드 완료"
    else
        log_error "Docker 이미지 빌드 실패"
        exit 1
    fi
}

# 이미지 정보 확인
inspect_image() {
    log_info "빌드된 이미지 정보 확인 중..."
    
    docker images | grep ${IMAGE_NAME}
    
    log_info "이미지 상세 정보:"
    docker inspect ${IMAGE_NAME}:${IMAGE_TAG} | jq '.[0].Config.Labels // {}'
}

# 이미지 푸시 (선택사항)
push_image() {
    if [ "${PUSH_IMAGE}" = "true" ]; then
        log_info "Docker 이미지 푸시 중..."
        
        docker push ${IMAGE_NAME}:${IMAGE_TAG}
        docker push ${IMAGE_NAME}:latest
        
        if [ $? -eq 0 ]; then
            log_success "Docker 이미지 푸시 완료"
        else
            log_error "Docker 이미지 푸시 실패"
            exit 1
        fi
    else
        log_info "이미지 푸시를 건너뜁니다. (PUSH_IMAGE=true로 설정하여 푸시 가능)"
    fi
}

# 정리
cleanup() {
    log_info "빌드 정리 중..."
    
    # 중간 이미지 정리
    docker image prune -f
    
    log_success "정리 완료"
}

# 메인 실행
main() {
    log_info "🚀 Kong Gateway eBPF Monitor 빌드 시작"
    
    check_requirements
    check_go_modules
    check_ebpf_headers
    build_image
    inspect_image
    push_image
    cleanup
    
    log_success "✅ 빌드 프로세스 완료"
    log_info "이미지: ${IMAGE_NAME}:${IMAGE_TAG}"
    log_info "Kubernetes에 배포하려면 다음 명령을 사용하세요:"
    log_info "kubectl apply -f daemonset.yaml"
}

# 도움말
show_help() {
    echo "Kong Gateway eBPF Monitor 빌드 스크립트"
    echo ""
    echo "사용법: $0 [옵션]"
    echo ""
    echo "옵션:"
    echo "  -h, --help          이 도움말 표시"
    echo "  -p, --push          빌드 후 이미지 푸시"
    echo "  -t, --tag TAG       이미지 태그 지정 (기본값: 0.0.2)"
    echo "  -n, --name NAME     이미지 이름 지정"
    echo ""
    echo "환경 변수:"
    echo "  IMAGE_NAME          이미지 이름 (기본값: harbor.ops.action.cloudz.co.kr/apim/kong-watcher)"
    echo "  IMAGE_TAG           이미지 태그 (기본값: 0.0.2)"
    echo "  BUILD_PLATFORM      빌드 플랫폼 (기본값: linux/amd64)"
    echo "  PUSH_IMAGE          이미지 푸시 여부 (true/false)"
    echo ""
    echo "예시:"
    echo "  $0                          # 기본 빌드"
    echo "  $0 --push                   # 빌드 후 푸시"
    echo "  $0 --tag 1.0.0 --push       # 특정 태그로 빌드 후 푸시"
}

# 명령행 인수 처리
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -p|--push)
            PUSH_IMAGE=true
            shift
            ;;
        -t|--tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        *)
            log_error "알 수 없는 옵션: $1"
            show_help
            exit 1
            ;;
    esac
done

# 메인 실행
main
