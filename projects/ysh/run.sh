#!/bin/bash

# eBPF Storage Exporter 실행 스크립트

echo "eBPF Storage Exporter 시작..."

# BCC (BPF Compiler Collection) 설치 확인
if ! python3 -c "import bcc" 2>/dev/null; then
    echo "BCC 설치 중..."
    # 패키지 목록 업데이트
    apt-get update
    # BCC 관련 패키지 설치
    apt-get install -y python3-bpfcc bpfcc-tools
fi

# eBPF Storage Exporter 실행
python3 storage_exporter.py
