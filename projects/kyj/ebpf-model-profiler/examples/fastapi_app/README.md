# FastAPI Example Application

This is a sample FastAPI application for testing the eBPF Model Serving Latency Profiler.

## Features

- RESTful API with prediction endpoints
- Simulates file I/O (reading model weights)
- Simulates inference time
- Batch prediction support

## Running the Application

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the server

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

Or:

```bash
python app.py
```

### 3. Test the API

```bash
# Health check
curl http://localhost:8000/health

# Single prediction
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"data": [1.0, 2.0, 3.0], "model_name": "default"}'
```

## Profiling with eBPF

### 1. Find the uvicorn process ID

```bash
ps aux | grep uvicorn
```

### 2. Start the profiler

```bash
sudo ebpf-profiler start --pid <PID>
```

### 3. Generate load

```bash
cd ../load_test
python simple_test.py
```

### 4. View results

The profiler will show:
- File I/O latency (reading model_weights.bin)
- Network I/O latency (HTTP requests/responses)
- Sleep latency (simulated inference time)
- Overall request latency breakdown

## Expected Syscalls

When profiling this application, you should see:

- `openat`: Opening the model weights file
- `read`: Reading model weights from disk
- `sendto`/`recvfrom`: Network I/O for HTTP
- `nanosleep`: Simulated inference time
- `write`: Writing HTTP responses
