#!/bin/bash
# scripts/install_deps.sh - Install Python dependencies

set -e

echo "Installing eBPF Model Profiler dependencies..."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
echo "Python version: $python_version"

# Install requirements
pip3 install --upgrade pip
pip3 install -r requirements.txt

echo "✓ Dependencies installed successfully"
