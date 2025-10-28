#!/bin/bash
set -euox pipefail

cd ~

wget https://github.com/microsoft/WSL2-Linux-Kernel/archive/refs/tags/linux-msft-wsl-6.6.87.2.tar.gz
tar xvf linux-msft-wsl-6.6.87.2.tar.gz
cd WSL2-Linux-Kernel-linux-msft-wsl-6.6.87.2/tools/bpf/bpftool

make
sudo make install

ls /usr/local/sbin/bpftool
bpftool version

bpftool btf dump file /sys/kernel/btf/vmlinux format c > ~/vmlinux.h