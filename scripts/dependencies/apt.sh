#!/bin/bash
set -euo pipefail

sudo apt update \
&& sudo apt install --yes \
  git \
  build-essential \
  libssl-dev \
  zlib1g-dev \
  libbz2-dev \
  liblzma-dev \
  libreadline-dev \
  libsqlite3-dev \
  wget \
  curl \
  libncurses5-dev \
  libncursesw5-dev \
  xz-utils \
  tk-dev \
  clang \
  llvm \
  libelf-dev \
  bpftool \
  graphviz \
  net-tools \
  bpftrace \
&& sudo apt autoremove --yes --allow-remove-essential \
&& sudo apt clean