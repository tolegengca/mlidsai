from scapy.all import sniff, IP, TCP, UDP, Ether
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, UDP
from prometheus_client import start_http_server, Counter, Gauge
import threading
import time
from abc import ABC, abstractmethod
from typing import Dict, Tuple, Any, List, Optional
from collections import defaultdict
import random
import argparse

class AnomalyDetector(ABC):
    @abstractmethod
    def detect_anomaly(self, packet: Ether, session_info: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Detect if the packet is anomalous
        Returns: (is_anomaly: bool, anomaly_type: Optional[str])
        """
        pass

    @abstractmethod
    def get_supported_anomaly_types(self) -> List[str]:
        """Return list of supported anomaly types"""
        pass

class RandomAnomalyDetector(AnomalyDetector):
    def __init__(self):
        self.anomaly_types = ["suspicious_payload", "unusual_protocol", "high_frequency"]

    def detect_anomaly(self, packet: Ether, session_info: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        # Randomly decide if packet is anomalous (20% chance)
        if random.random() < 0.2:
            return True, random.choice(self.anomaly_types)
        return False, None

    def get_supported_anomaly_types(self) -> List[str]:
        return self.anomaly_types

class SessionTable:
    def __init__(self, ttl_seconds: int = 60):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.ttl_seconds = ttl_seconds
        self.lock = threading.Lock()
        self._start_cleanup_thread()

    def _get_session_key(self, packet: Ether) -> str:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto = "TCP"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                proto = "UDP"
            else:
                return None
            
            # Sort IPs and ports to ensure same session key for both directions
            if src_ip > dst_ip or (src_ip == dst_ip and src_port > dst_port):
                src_ip, dst_ip = dst_ip, src_ip
                src_port, dst_port = dst_port, src_port
            
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        return None

    def get(self, packet: Ether, key: str, default: Any = None) -> Any:
        session_key = self._get_session_key(packet)
        if session_key and session_key in self.sessions:
            return self.sessions[session_key].get(key, default)
        return default

    def set(self, packet: Ether, key: str, value: Any) -> None:
        session_key = self._get_session_key(packet)
        if session_key:
            with self.lock:
                if session_key not in self.sessions:
                    self.sessions[session_key] = {
                        "first_seen": time.time(),
                        "last_seen": time.time(),
                        "total_bytes": 0,
                        "total_packets": 0
                    }
                self.sessions[session_key][key] = value
                self.sessions[session_key]["last_seen"] = time.time()

    def _cleanup_expired_sessions(self):
        while True:
            current_time = time.time()
            with self.lock:
                expired_keys = [
                    key for key, session in self.sessions.items()
                    if current_time - session["last_seen"] > self.ttl_seconds
                ]
                for key in expired_keys:
                    del self.sessions[key]
            time.sleep(1)

    def _start_cleanup_thread(self):
        cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions, daemon=True)
        cleanup_thread.start()

class TrafficMonitor:
    def __init__(self, interface: str, anomaly_detector: AnomalyDetector):
        self.interface = interface
        self.anomaly_detector = anomaly_detector
        self.session_table = SessionTable()
        
        # Initialize Prometheus metrics
        self.total_bytes = Counter('mlidsai_total_bytes', 'Total bytes processed')
        self.total_packets = Counter('mlidsai_total_packets', 'Total packets processed')
        self.total_sessions = Counter('mlidsai_total_sessions', 'Total new sessions detected')
        self.normal_bytes = Counter('mlidsai_normal_bytes', 'Total normal bytes')
        self.normal_packets = Counter('mlidsai_normal_packets', 'Total normal packets')
        self.anomaly_bytes = Counter('mlidsai_anomaly_bytes', 'Total anomaly bytes')
        self.anomaly_packets = Counter('mlidsai_anomaly_packets', 'Total anomaly packets')
        
        # Initialize anomaly metrics with type label
        self.anomaly_type_bytes = Counter('mlidsai_anomaly_type_bytes', 'Bytes per anomaly type', ['type'])
        self.anomaly_type_packets = Counter('mlidsai_anomaly_type_packets', 'Packets per anomaly type', ['type'])

    def process_packet(self, packet: Ether):
        if IP not in packet:
            return

        packet_size = len(packet)
        session_key = self.session_table._get_session_key(packet)
        
        # Update session information
        if session_key:
            if session_key not in self.session_table.sessions:
                self.total_sessions.inc()
            
            current_bytes = self.session_table.get(packet, "total_bytes", 0)
            current_packets = self.session_table.get(packet, "total_packets", 0)
            
            self.session_table.set(packet, "total_bytes", current_bytes + packet_size)
            self.session_table.set(packet, "total_packets", current_packets + 1)

        # Update global statistics
        self.total_bytes.inc(packet_size)
        self.total_packets.inc()

        # Detect anomaly
        is_anomaly, anomaly_type = self.anomaly_detector.detect_anomaly(
            packet, self.session_table.sessions.get(session_key, {}))

        if is_anomaly:
            self.anomaly_bytes.inc(packet_size)
            self.anomaly_packets.inc()
            if anomaly_type:
                self.anomaly_type_bytes.labels(type=anomaly_type).inc(packet_size)
                self.anomaly_type_packets.labels(type=anomaly_type).inc()
        else:
            self.normal_bytes.inc(packet_size)
            self.normal_packets.inc()

    def start(self):
        # Start Prometheus metrics server
        start_http_server(8000)
        
        # Start packet capture
        sniff(iface=self.interface, prn=self.process_packet, store=0)

def parse_args():
    parser = argparse.ArgumentParser(description='Network Traffic Monitor with Anomaly Detection')
    parser.add_argument('-i', '--interface', required=True,
                      help='Network interface to capture packets from')
    parser.add_argument('-p', '--prometheus-port', type=int, default=8000,
                      help='Port for Prometheus metrics server (default: 8000)')
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Create and start the traffic monitor
    detector = RandomAnomalyDetector()
    monitor = TrafficMonitor(args.interface, detector)
    monitor.start()

if __name__ == "__main__":
    main()
