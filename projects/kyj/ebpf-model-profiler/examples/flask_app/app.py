# examples/flask_app/app.py - Sample Flask model serving application
"""
Example Flask application for testing the eBPF profiler.
Simulates a simple model serving API.
"""

from flask import Flask, request, jsonify
import time
import os
import tempfile

app = Flask(__name__)

# Simulate model weights file
MODEL_WEIGHTS_FILE = os.path.join(tempfile.gettempdir(), "flask_model_weights.bin")


def init_model_weights():
    """Initialize dummy model weights file"""
    if not os.path.exists(MODEL_WEIGHTS_FILE):
        with open(MODEL_WEIGHTS_FILE, 'wb') as f:
            f.write(b'0' * (5 * 1024 * 1024))  # 5MB file


init_model_weights()


@app.route('/')
def root():
    """Root endpoint"""
    return jsonify({"message": "Flask Model Serving API", "status": "healthy"})


@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy"})


@app.route('/predict', methods=['POST'])
def predict():
    """
    Prediction endpoint.

    Expects JSON body with:
    {
        "data": [list of floats],
        "model_name": "model name"
    }
    """
    start_time = time.time()

    data = request.json
    if not data or 'data' not in data:
        return jsonify({"error": "Invalid request"}), 400

    input_data = data.get('data', [])
    model_name = data.get('model_name', 'default')

    # Simulate reading model weights
    try:
        with open(MODEL_WEIGHTS_FILE, 'rb') as f:
            _ = f.read(512 * 1024)  # Read 512KB
    except Exception as e:
        return jsonify({"error": f"Failed to load model: {e}"}), 500

    # Simulate inference
    time.sleep(0.03)  # 30ms

    # Generate prediction
    prediction = sum(input_data) / len(input_data) if input_data else 0.0
    confidence = 0.80

    latency_ms = (time.time() - start_time) * 1000

    return jsonify({
        "prediction": prediction,
        "confidence": confidence,
        "latency_ms": latency_ms
    })


if __name__ == '__main__':
    print(f"Model weights file: {MODEL_WEIGHTS_FILE}")
    app.run(host='0.0.0.0', port=5000, debug=False)
