.PHONY: all generate build clean run

all: generate build

generate:
	go generate ./...

build: generate
	go build -o monitor .

clean:
	rm -f monitor tcp_monitor_*.go tcp_monitor_*.o

run: build
	sudo ./monitor

docker-build:
	docker build -t yhc0818/tcp-monitor:latest --push .
