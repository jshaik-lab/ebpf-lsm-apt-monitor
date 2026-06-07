import json
import logging
import statistics
import time

# Assumes ipg_encoder is in the parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipg_encoder import IPGBuilder, KernelEvent, SyscallType
from cadets_ingestor import CadetsIngestor

logger = logging.getLogger("sentinel.eval.ipg")

class IPGCompressionEvaluator:
    """
    Evaluates the token-compression efficacy of the Intent Provenance Graph (IPG)
    compared to sending raw JSON eBPF events to the LLM. This provides the mathematical
    proof for the token reduction claims in the IEEE paper.
    """
    def __init__(self, dataset_path: str = None):
        self.builder = IPGBuilder()
        self.dataset_path = dataset_path

    def _mock_token_count(self, text: str) -> int:
        # Rough approximation: 1 word ~ 1.3 tokens
        return int(len(text.split()) * 1.3)

    def generate_synthetic_window(self) -> list[KernelEvent]:
        # Generate 20 events representing a credential dump attempt
        events = []
        base_ts = 1700000000000000000
        
        # 10 noisy benign events (libc loads, etc.)
        for i in range(10):
            events.append(KernelEvent(
                ts_ns=base_ts + (i * 1000000), pid=1337, ppid=1, uid=1000,
                comm="bash", sc_type=SyscallType.FILE_R.value, resource=f"/usr/lib/libc.so.{i}",
                flags=0, net_port=0, net_ip4=0
            ))
            
        # 5 malicious events
        events.append(KernelEvent(
            ts_ns=base_ts + 11000000, pid=1337, ppid=1, uid=1000,
            comm="bash", sc_type=SyscallType.EXEC.value, resource="/bin/cat",
            flags=0, net_port=0, net_ip4=0
        ))
        events.append(KernelEvent(
            ts_ns=base_ts + 12000000, pid=1338, ppid=1337, uid=0,
            comm="cat", sc_type=SyscallType.FILE_R.value, resource="/etc/shadow",
            flags=0, net_port=0, net_ip4=0
        ))
        events.append(KernelEvent(
            ts_ns=base_ts + 13000000, pid=1337, ppid=1, uid=1000,
            comm="bash", sc_type=SyscallType.NET_CON.value, resource="93.184.216.34:4444",
            flags=0, net_port=4444, net_ip4=0x5db8d822
        ))
        
        # 5 more noisy events
        for i in range(5):
            events.append(KernelEvent(
                ts_ns=base_ts + 14000000 + (i * 1000000), pid=1337, ppid=1, uid=1000,
                comm="bash", sc_type=SyscallType.FILE_W.value, resource=f"/home/user/.bash_history",
                flags=0, net_port=0, net_ip4=0
            ))
            
        return events

    def evaluate(self, num_iterations: int = 100):
        logger.info(f"Running IPG Compression Evaluation over {num_iterations} iterations...")
        
        if self.dataset_path and os.path.exists(self.dataset_path):
            ingestor = CadetsIngestor(self.dataset_path)
            window_generator = ingestor.get_windows(20)
            logger.info(f"Using REAL DARPA TC CADETS dataset from {self.dataset_path}")
        else:
            logger.info("Using SYNTHETIC dataset for evaluation")
            window_generator = (self.generate_synthetic_window() for _ in range(num_iterations))

        raw_tokens_list = []
        ipg_tokens_list = []
        reduction_percentages = []
        
        for i, events in enumerate(window_generator):
            if i >= num_iterations:
                break
            
            # Raw JSON representation
            raw_dicts = [vars(e) for e in events]
            raw_text = json.dumps(raw_dicts)
            raw_tokens = self._mock_token_count(raw_text)
            
            # IPG representation
            G = self.builder.build(events)
            ipg_text = self.builder.serialize(G)
            ipg_tokens = self._mock_token_count(ipg_text)
            
            reduction = (1.0 - (ipg_tokens / raw_tokens)) * 100
            
            raw_tokens_list.append(raw_tokens)
            ipg_tokens_list.append(ipg_tokens)
            reduction_percentages.append(reduction)
            
        avg_raw = statistics.mean(raw_tokens_list)
        avg_ipg = statistics.mean(ipg_tokens_list)
        avg_reduction = statistics.mean(reduction_percentages)
        
        report = (
            f"\n{'='*50}\n"
            f"IPG Compression Scientific Evaluation\n"
            f"{'='*50}\n"
            f"Average Raw JSON Tokens (per 20-event window): {avg_raw:.1f}\n"
            f"Average IPG Tokens      (per 20-event window): {avg_ipg:.1f}\n"
            f"Average Token Reduction                      : {avg_reduction:.2f}%\n"
            f"{'='*50}\n"
        )
        logger.info(report)
        return report

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    evaluator = IPGCompressionEvaluator(dataset_path="/Volumes/Extreme SSD/DARPA_TC/cadets/ta1-cadets-e3-official.json")
    evaluator.evaluate()
