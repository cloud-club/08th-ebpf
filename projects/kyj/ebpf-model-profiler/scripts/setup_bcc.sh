#!/bin/bash
# scripts/setup_bcc.sh - Install BCC (BPF Compiler Collection)

set -e

echo "Installing BCC (BPF Compiler Collection)..."

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS"

# Install based on OS
case "$OS" in
    ubuntu|debian)
        echo "Installing BCC for Ubuntu/Debian..."
        sudo apt-get update
        sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r)
        sudo apt-get install -y python3-bpfcc
        ;;

    fedora|rhel|centos)
        echo "Installing BCC for Fedora/RHEL/CentOS..."
        sudo dnf install -y bcc-tools kernel-devel-$(uname -r)
        sudo dnf install -y python3-bcc
        ;;

    *)
        echo "Unsupported OS: $OS"
        echo "Please install BCC manually from: https://github.com/iovisor/bcc/blob/master/INSTALL.md"
        exit 1
        ;;
esac

# Verify installation
if python3 -c "import bcc" 2>/dev/null; then
    echo "✓ BCC installed successfully"
else
    echo "✗ BCC installation failed"
    exit 1
fi
