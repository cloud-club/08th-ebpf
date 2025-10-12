# examples/load_test/simple_test.py - Simple load testing script
"""
Simple load testing script for model serving API.
Sends multiple requests to test the profiler.
"""

import requests
import time
import random
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List


class SimpleLoadTester:
    """Simple load tester for model serving APIs"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        """
        Initialize load tester.

        Args:
            base_url: Base URL of the API
        """
        self.base_url = base_url

    def send_prediction_request(self) -> Dict:
        """
        Send a single prediction request.

        Returns:
            Response dictionary
        """
        data = {
            "data": [random.random() for _ in range(10)],
            "model_name": "default"
        }

        start_time = time.time()

        try:
            response = requests.post(
                f"{self.base_url}/predict",
                json=data,
                timeout=10
            )

            latency_ms = (time.time() - start_time) * 1000

            return {
                "status_code": response.status_code,
                "latency_ms": latency_ms,
                "success": response.status_code == 200
            }

        except Exception as e:
            return {
                "status_code": 0,
                "latency_ms": 0,
                "success": False,
                "error": str(e)
            }

    def run_load_test(self, num_requests: int = 100, num_workers: int = 4):
        """
        Run load test with multiple requests.

        Args:
            num_requests: Total number of requests to send
            num_workers: Number of concurrent workers
        """
        print(f"Starting load test...")
        print(f"Target: {self.base_url}")
        print(f"Requests: {num_requests}")
        print(f"Workers: {num_workers}\n")

        results = []
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [
                executor.submit(self.send_prediction_request)
                for _ in range(num_requests)
            ]

            for i, future in enumerate(futures, 1):
                result = future.result()
                results.append(result)

                if i % 10 == 0:
                    print(f"Completed {i}/{num_requests} requests...")

        total_time = time.time() - start_time

        # Print summary
        self.print_summary(results, total_time)

    def print_summary(self, results: List[Dict], total_time: float):
        """
        Print test summary.

        Args:
            results: List of result dictionaries
            total_time: Total test duration
        """
        successful = [r for r in results if r['success']]
        failed = len(results) - len(successful)

        if successful:
            latencies = [r['latency_ms'] for r in successful]
            avg_latency = sum(latencies) / len(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)
            sorted_latencies = sorted(latencies)
            p95_latency = sorted_latencies[int(len(sorted_latencies) * 0.95)]
        else:
            avg_latency = min_latency = max_latency = p95_latency = 0

        print("\n" + "="*60)
        print("LOAD TEST SUMMARY")
        print("="*60)
        print(f"Total Requests:    {len(results)}")
        print(f"Successful:        {len(successful)}")
        print(f"Failed:            {failed}")
        print(f"Total Time:        {total_time:.2f}s")
        print(f"Requests/sec:      {len(results)/total_time:.2f}")
        print(f"\nLatency Statistics:")
        print(f"  Average:         {avg_latency:.2f}ms")
        print(f"  Min:             {min_latency:.2f}ms")
        print(f"  Max:             {max_latency:.2f}ms")
        print(f"  P95:             {p95_latency:.2f}ms")
        print("="*60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple load tester for model serving API")
    parser.add_argument('--url', default='http://localhost:8000', help='API base URL')
    parser.add_argument('--requests', type=int, default=100, help='Number of requests')
    parser.add_argument('--workers', type=int, default=4, help='Number of concurrent workers')

    args = parser.parse_args()

    tester = SimpleLoadTester(base_url=args.url)
    tester.run_load_test(num_requests=args.requests, num_workers=args.workers)
