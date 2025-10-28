#!/bin/bash
set -euox pipefail

sudo apt update \
&& sudo apt install --yes \
  git \
  build-essential \
  clang \
  llvm \
  libelf-dev \
  libbpf-dev \
  bpftrace \
  wget \
  curl \
  net-tools \
&& sudo apt autoremove --yes --allow-remove-essential \
&& sudo apt clean