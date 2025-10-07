BIN_DIR := bin
TARGET := $(BIN_DIR)/ebpf-router
GO_FLAGS := -ldflags="-s -w"

all: build

deps:
	@go mod tidy
	@go mod download

build: deps
	@mkdir -p $(BIN_DIR)
	@go build $(GO_FLAGS) -o $(TARGET) cmd/router/main.go

dev:
	@mkdir -p $(BIN_DIR)
	@go build -o $(TARGET) cmd/router/main.go

run: build
	@sudo ./$(TARGET)

test:
	@go test -v ./...

clean:
	@rm -rf $(BIN_DIR)
	@go clean

help:
	@echo "Usage"
	@echo "  build  - 빌드"
	@echo "  dev    - 개발 빌드"
	@echo "  run    - 실행"
	@echo "  test   - 테스트"
	@echo "  clean  - 빌드 정리"
	@echo "  deps   - 의존성 설치"

.PHONY: all build dev run test clean help deps
