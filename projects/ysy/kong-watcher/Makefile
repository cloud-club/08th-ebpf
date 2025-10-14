# Kong Gateway eBPF Monitor Makefile

# 변수 설정
IMG ?= harbor.ops.action.cloudz.co.kr/apim/kong-watcher:0.0.1
PODMAN_BUILD_ARGS ?= --tls-verify=false

.PHONY: all build clean generate test podman-build podman-push podman-buildx run k8s-deploy k8s-delete k8s-status k8s-logs

# 기본 타겟
all: generate build

# eBPF 코드 생성 (amd64만)
generate:
	@echo "eBPF 코드 생성 중..."
	GOOS=linux GOARCH=amd64 go generate

# Go 애플리케이션 빌드
build: generate
	@echo "Go 애플리케이션 빌드 중..."
	@echo "불필요한 아키텍처 파일 제거 중..."
	rm -f bpf_bpfeb.go kprobe_bpfeb.go uprobe_bpfeb.go
	go build -o kong-watcher *.go


# 테스트 실행
test:
	@echo "테스트 실행 중..."
	go test -v ./...

# 정리
clean:
	@echo "빌드 파일 정리 중..."
	rm -f kong-watcher
	rm -f bpf_*.go
	rm -f bpf_*.o
	rm -f kprobe_*.go
	rm -f kprobe_*.o
	rm -f uprobe_*.go
	rm -f uprobe_*.o

# Podman 이미지 빌드 (amd64 전용)
podman-build: ## Build podman image for amd64
	@echo "🏗️  Building podman image for amd64..."
	podman build $(PODMAN_BUILD_ARGS) --platform linux/amd64 --build-arg TARGETOS=linux --build-arg TARGETARCH=amd64 --tag ${IMG} -f Dockerfile .
	@echo "✅ Podman build completed successfully"

# Podman 이미지 푸시
podman-push: ## Push podman image
	@echo "📤 Pushing podman image..."
	podman push --tls-verify=false --retry=3 --retry-delay=5s --compression-format=gzip --compression-level=6 ${IMG}
	@echo "✅ Podman push completed successfully"

# Podman 빌드 및 푸시 (amd64 전용)
podman-buildx: podman-build podman-push ## Build and push podman image for amd64
	@echo "✅ amd64 build and push completed successfully"

# 로컬 실행 (개발용)
run: build
	@echo "로컬에서 실행 중..."
	sudo ./kong-watcher

# 의존성 설치
deps:
	@echo "의존성 설치 중..."
	go mod tidy
	go get github.com/cilium/ebpf
	go get github.com/cilium/ebpf/cmd/bpf2go

# 개발 환경 설정
dev-setup: deps
	@echo "개발 환경 설정 중..."
	@echo "필요한 도구들:"
	@echo "- clang (eBPF 컴파일용)"
	@echo "- llvm (eBPF 컴파일용)"
	@echo "- bpftool (eBPF 디버깅용)"
	@echo "- podman (컨테이너 빌드용)"
	@echo ""
	@echo "Ubuntu/Debian:"
	@echo "sudo apt-get install clang llvm bpftool podman"
	@echo ""
	@echo "CentOS/RHEL:"
	@echo "sudo yum install clang llvm bpftool podman"
	@echo ""
	@echo "macOS:"
	@echo "brew install llvm podman"

# Kubernetes 배포
k8s-deploy: ## Kubernetes에 배포
	@echo "🚀 Kubernetes에 배포 중..."
	kubectl apply -f deployment.yaml
	@echo "✅ 배포 완료"

k8s-delete: ## Kubernetes에서 삭제
	@echo "🗑️  Kubernetes에서 삭제 중..."
	kubectl delete -f deployment.yaml
	@echo "✅ 삭제 완료"

k8s-status: ## Kubernetes 배포 상태 확인
	@echo "📊 배포 상태 확인 중..."
	kubectl get pods -n default
	kubectl get deployment -n default
	kubectl get service -n default

k8s-logs: ## Kubernetes Pod 로그 확인
	@echo "📋 Pod 로그 확인 중..."
	kubectl logs -f deployment/kong-watcher -n default

# 도움말
help:
	@echo "사용 가능한 명령어:"
	@echo "  make all              - eBPF 코드 생성 및 빌드"
	@echo "  make generate         - eBPF 코드 생성"
	@echo "  make build            - Go 애플리케이션 빌드"
	@echo "  make test             - 테스트 실행"
	@echo "  make clean            - 빌드 파일 정리"
	@echo "  make podman-build     - Podman 이미지 빌드"
	@echo "  make podman-push      - Podman 이미지 푸시"
	@echo "  make podman-buildx    - Podman amd64 빌드 및 푸시"
	@echo "  make run              - 로컬에서 실행"
	@echo "  make deps             - 의존성 설치"
	@echo "  make dev-setup        - 개발 환경 설정"
	@echo "  make k8s-deploy       - Kubernetes에 배포"
	@echo "  make k8s-delete       - Kubernetes에서 삭제"
	@echo "  make k8s-status       - Kubernetes 배포 상태 확인"
	@echo "  make k8s-logs         - Kubernetes Pod 로그 확인"
	@echo "  make help             - 이 도움말 표시"
	@echo ""
	@echo "환경 변수:"
	@echo "  IMG                   - 이미지 이름:태그 (기본값: harbor.ops.action.cloudz.co.kr/apim/kong-watcher:0.0.1)"
	@echo "  PODMAN_BUILD_ARGS     - Podman 빌드 인수 (기본값: --tls-verify=false)"
