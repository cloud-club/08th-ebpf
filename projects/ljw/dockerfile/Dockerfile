FROM docker.io/library/golang:1.23.4-alpine3.21
WORKDIR /workspace
RUN apk update
RUN apk add \
    bash \
    curl \
    build-base \
    clang \
    llvm \
    linux-headers \
    libbpf-dev
RUN mount -t tracefs none /sys/kernel/tracing