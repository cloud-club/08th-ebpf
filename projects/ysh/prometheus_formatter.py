class PrometheusFormatter:
    """메트릭 데이터를 Prometheus 형식으로 변환하는 클래스"""
    
    @staticmethod
    def format_metrics(metrics):
        output = []
        
        for metric, value in metrics.items():
            output.append(f"# HELP {metric} Storage rate metric")
            output.append(f"# TYPE {metric} gauge")

            output.append(f"{metric} {value}")
            output.append("")
        
        # 모든 라인을 개행문자로 연결하여 바이트로 반환
        return "\n".join(output).encode('utf-8')
