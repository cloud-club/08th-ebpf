from http.server import BaseHTTPRequestHandler
from prometheus_formatter import PrometheusFormatter

class MetricsHandler(BaseHTTPRequestHandler):
    
    def __init__(self, collector, *args, **kwargs):
        self.collector = collector
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()

            metrics = self.collector.get_metrics()
            formatted_metrics = PrometheusFormatter.format_metrics(metrics)
            
            # 클라이언트에게 메트릭 데이터 전송
            self.wfile.write(formatted_metrics)
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """HTTP 요청 로그 출력 비활성화 (콘솔 정리용)"""
        pass
