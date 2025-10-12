# examples/fastapi_app/app.py - Sample FastAPI model serving application
"""
Example FastAPI application for testing the eBPF profiler.
Simulates a model serving API with file I/O and inference.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import time
import os
import tempfile
from typing import Dict, List

app = FastAPI(title="Model Serving API")


class PredictionRequest(BaseModel):
    """Request model for predictions"""
    data: List[float]
    model_name: str = "default"


class PredictionResponse(BaseModel):
    """Response model for predictions"""
    prediction: float
    confidence: float
    latency_ms: float


# Simulate model weights file
MODEL_WEIGHTS_FILE = os.path.join(tempfile.gettempdir(), "model_weights.bin")


def init_model_weights():
    """Initialize dummy model weights file"""
    if not os.path.exists(MODEL_WEIGHTS_FILE):
        # Create a 10MB dummy file
        with open(MODEL_WEIGHTS_FILE, 'wb') as f:
            f.write(b'0' * (10 * 1024 * 1024))


@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    init_model_weights()
    print(f"Model weights file: {MODEL_WEIGHTS_FILE}")


@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "Model Serving API", "status": "healthy"}


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest) -> PredictionResponse:
    """
    Prediction endpoint that simulates model inference.

    This endpoint:
    1. Reads model weights from disk (file I/O)
    2. Simulates inference time with sleep
    3. Returns prediction results
    """
    start_time = time.time()

    # Simulate reading model weights (file I/O syscalls)
    try:
        with open(MODEL_WEIGHTS_FILE, 'rb') as f:
            # Read first 1MB
            _ = f.read(1024 * 1024)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load model: {e}")

    # Simulate model inference time
    # This will show up as nanosleep syscall in the profiler
    inference_time = 0.05  # 50ms
    time.sleep(inference_time)

    # Simulate prediction result
    prediction = sum(request.data) / len(request.data) if request.data else 0.0
    confidence = 0.85 + (hash(request.model_name) % 15) / 100.0

    latency_ms = (time.time() - start_time) * 1000

    return PredictionResponse(
        prediction=prediction,
        confidence=confidence,
        latency_ms=latency_ms
    )


@app.post("/predict_batch")
async def predict_batch(requests: List[PredictionRequest]) -> List[PredictionResponse]:
    """
    Batch prediction endpoint.

    Processes multiple prediction requests in batch.
    """
    results = []

    for req in requests:
        result = await predict(req)
        results.append(result)

    return results


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
