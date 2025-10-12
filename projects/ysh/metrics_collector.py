from bcc import BPF
import time

class MetricsCollector:
    
    def __init__(self):
        with open('./ebpf/ebpf_program.c', 'r') as f:
            bpf_program = f.read()

        self.bpf = BPF(text=bpf_program)
        
        # 이전 값과 시간 저장
        self.prev_stats = None
        self.prev_time = None
        
        # 메트릭 데이터 초기화
        self.metrics = {
            'storage_read_bytes_per_sec': 0,
            'storage_write_bytes_per_sec': 0,
            'storage_read_ops_per_sec': 0,
            'storage_write_ops_per_sec': 0,
        }
    
    def _calculate_rate(self, current_val, prev_val, time_diff):
        return int((current_val - prev_val) / time_diff)
    
    def collect_metrics(self):
        try:
            key = self.bpf["io_stats"].Key(0)
            stats = self.bpf["io_stats"][key]
            current_time = time.time()

            if self.prev_stats and self.prev_time:
                time_diff = current_time - self.prev_time
                if time_diff > 0:
                    self.metrics['storage_read_bytes_per_sec'] = self._calculate_rate(
                        stats.read_bytes, self.prev_stats.read_bytes, time_diff)
                    self.metrics['storage_write_bytes_per_sec'] = self._calculate_rate(
                        stats.write_bytes, self.prev_stats.write_bytes, time_diff)
                    self.metrics['storage_read_ops_per_sec'] = self._calculate_rate(
                        stats.read_count, self.prev_stats.read_count, time_diff)
                    self.metrics['storage_write_ops_per_sec'] = self._calculate_rate(
                        stats.write_count, self.prev_stats.write_count, time_diff)

            self.prev_stats = stats
            self.prev_time = current_time
                
        except (KeyError, ValueError) as e:
            print(f"DEBUG: No data in BPF map yet: {e}")
            pass
    
    def get_metrics(self):
        self.collect_metrics()
        return self.metrics
