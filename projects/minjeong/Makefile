.PHONY: all deps generate build run clean

BIN_DIR := bin
BIN := $(BIN_DIR)/ebpf_pcap

all: build

deps:
	@go mod tidy
	@go mod download
	@go install github.com/cilium/ebpf/cmd/bpf2go@latest

generate: deps
	@go generate ./...

build: generate
	@mkdir -p $(BIN_DIR)
	@go build -o $(BIN) ./cmd/main.go

run:
	@sudo ./$(BIN)

clean:
	@rm -rf $(BIN_DIR)
	@rm -f internal/bpf/*_bpfel.go
	@rm -f internal/bpf/*_bpfeb.go
	@rm -f internal/bpf/*_bpfel.o
	@rm -f internal/bpf/*_bpfeb.o