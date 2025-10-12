FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    linux-headers-generic \
    libbpf-dev \
    bpfcc-tools \
    python3-bpfcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
COPY storage_exporter.py .

RUN pip3 install -r requirements.txt

EXPOSE 8080

CMD ["python3", "storage_exporter.py"]
