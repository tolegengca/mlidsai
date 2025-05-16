from scapy.all import sniff, IP, TCP, UDP, Ether, ICMP
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, UDP
from prometheus_client import start_http_server, Counter
import threading
import time
from abc import ABC, abstractmethod
from typing import Dict, Tuple, Any, List, Optional
import random
import argparse
from collections import defaultdict
import logging

# Configure logging
logger = logging.getLogger("mlidsai")
logger.setLevel(logging.INFO)


class AnomalyDetector(ABC):
    @abstractmethod
    def detect_anomaly(
        self, packet: Ether, session_info: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Detect if the packet is anomalous
        Returns: (is_anomaly: bool, anomaly_type: Optional[str])
        """
        pass

    @abstractmethod
    def get_supported_anomaly_types(self) -> List[str]:
        """Return list of supported anomaly types"""
        pass


class StaticAnomalyDetector(AnomalyDetector):
    def __init__(self):
        self.anomaly_types = ["syn_flood", "udp_flood", "icmp_flood"]

        # Time window for rate calculation (in seconds)
        self.time_window = 5

        # Thresholds for different types of attacks
        self.thresholds = {
            "syn_flood": 50,  # packets per time window
            "udp_flood": 30,  # packets per time window
            "icmp_flood": 20,  # packets per time window
        }

        # Store packet counts in time windows
        self.packet_counts = {
            "syn": defaultdict(int),
            "udp": defaultdict(int),
            "icmp": defaultdict(int),
        }
        self.last_cleanup = int(time.time())

        # Lock for thread safety
        self.lock = threading.Lock()

    def _cleanup_old_windows(self):
        current_time = int(time.time())
        if current_time - self.last_cleanup >= 1:  # Cleanup every second
            with self.lock:
                cutoff_time = current_time - self.time_window
                for proto in self.packet_counts:
                    # Remove old entries
                    self.packet_counts[proto] = defaultdict(
                        int,
                        {
                            k: v
                            for k, v in self.packet_counts[proto].items()
                            if k > cutoff_time
                        },
                    )
                self.last_cleanup = current_time

    def detect_anomaly(
        self, packet: Ether, session_info: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        if IP not in packet:
            return False, None

        current_time = int(time.time())
        self._cleanup_old_windows()

        with self.lock:
            # Check for SYN flood
            if TCP in packet and packet[TCP].flags == 0x02:  # SYN flag
                self.packet_counts["syn"][current_time] += 1
                syn_count = sum(self.packet_counts["syn"].values())
                if syn_count > self.thresholds["syn_flood"]:
                    logger.debug(f"Detected SYN flood: {syn_count} packets in window")
                    return True, "syn_flood"

            # Check for UDP flood
            if UDP in packet:
                self.packet_counts["udp"][current_time] += 1
                udp_count = sum(self.packet_counts["udp"].values())
                if udp_count > self.thresholds["udp_flood"]:
                    logger.debug(f"Detected UDP flood: {udp_count} packets in window")
                    return True, "udp_flood"

            # Check for ICMP flood
            if ICMP in packet:
                self.packet_counts["icmp"][current_time] += 1
                icmp_count = sum(self.packet_counts["icmp"].values())
                if icmp_count > self.thresholds["icmp_flood"]:
                    logger.debug(f"Detected ICMP flood: {icmp_count} packets in window")
                    return True, "icmp_flood"

        return False, None

    def get_supported_anomaly_types(self) -> List[str]:
        return self.anomaly_types


class RandomAnomalyDetector(AnomalyDetector):
    def __init__(self):
        self.anomaly_types = [
            "suspicious_payload",
            "unusual_protocol",
            "high_frequency",
        ]

    def detect_anomaly(
        self, packet: Ether, session_info: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        # Randomly decide if packet is anomalous (20% chance)
        if random.random() < 0.2:
            anomaly_type = random.choice(self.anomaly_types)
            logger.debug(f"Random anomaly detected: {anomaly_type}")
            return True, anomaly_type
        return False, None

    def get_supported_anomaly_types(self) -> List[str]:
        return self.anomaly_types


class SessionTable:
    def __init__(self, ttl_seconds: int = 60):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.ttl_seconds = ttl_seconds
        self.lock = threading.Lock()
        self._start_cleanup_thread()

    @staticmethod
    def get_session_key(packet: Ether) -> str | None:
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
            elif ICMP in packet:
                # For ICMP, we use type and code as ports
                src_port = packet[ICMP].type
                dst_port = packet[ICMP].code
                proto = "ICMP"
            else:
                return None

            # Sort IPs and ports to ensure same session key for both directions
            if src_ip > dst_ip or (src_ip == dst_ip and src_port > dst_port):
                src_ip, dst_ip = dst_ip, src_ip
                src_port, dst_port = dst_port, src_port

            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        return None

    def get(self, packet: Ether, key: str, default: Any = None) -> Any:
        session_key = self.get_session_key(packet)
        if session_key and session_key in self.sessions:
            return self.sessions[session_key].get(key, default)
        return default

    def set(self, packet: Ether, key: str, value: Any) -> None:
        session_key = self.get_session_key(packet)
        if session_key:
            with self.lock:
                if session_key not in self.sessions:
                    self.sessions[session_key] = {
                        "first_seen": time.time(),
                        "last_seen": time.time(),
                        "total_bytes": 0,
                        "total_packets": 0,
                        "is_anomaly": False,
                    }
                    logger.debug(f"New session created: {session_key}")
                self.sessions[session_key][key] = value
                self.sessions[session_key]["last_seen"] = time.time()

    def _cleanup_expired_sessions(self):
        while True:
            current_time = time.time()
            with self.lock:
                expired_keys = [
                    key
                    for key, session in self.sessions.items()
                    if current_time - session["last_seen"] > self.ttl_seconds
                ]
                for key in expired_keys:
                    logger.debug(f"Session expired: {key}")
                    del self.sessions[key]
            time.sleep(1)

    def _start_cleanup_thread(self):
        cleanup_thread = threading.Thread(
            target=self._cleanup_expired_sessions, daemon=True
        )
        cleanup_thread.start()


class TrafficMonitor:
    def __init__(self, interface: str, anomaly_detector: AnomalyDetector):
        self.interface = interface
        self.anomaly_detector = anomaly_detector
        self.session_table = SessionTable()

        # Initialize Prometheus metrics
        self.total_bytes = Counter("mlidsai_total_bytes", "Total bytes processed")
        self.total_packets = Counter("mlidsai_total_packets", "Total packets processed")
        self.total_sessions = Counter(
            "mlidsai_total_sessions", "Total new sessions detected"
        )
        self.normal_bytes = Counter("mlidsai_normal_bytes", "Total normal bytes")
        self.normal_packets = Counter("mlidsai_normal_packets", "Total normal packets")
        self.anomaly_bytes = Counter("mlidsai_anomaly_bytes", "Total anomaly bytes")
        self.anomaly_packets = Counter(
            "mlidsai_anomaly_packets", "Total anomaly packets"
        )

        # Initialize anomaly metrics with type label
        self.anomaly_type_bytes = Counter(
            "mlidsai_anomaly_type_bytes", "Bytes per anomaly type", ["type"]
        )
        self.anomaly_type_packets = Counter(
            "mlidsai_anomaly_type_packets", "Packets per anomaly type", ["type"]
        )

        # Initialize anomaly session counter
        self.anomaly_sessions = Counter(
            "mlidsai_anomaly_sessions", "Number of anomaly sessions detected", ["type"]
        )

        # Initialize all anomaly type counters to 0
        for anomaly_type in self.anomaly_detector.get_supported_anomaly_types():
            self.anomaly_type_bytes.labels(type=anomaly_type)
            self.anomaly_type_packets.labels(type=anomaly_type)
            self.anomaly_sessions.labels(type=anomaly_type)

    def process_packet(self, packet: Ether):
        if IP not in packet:
            return

        packet_size = len(packet)
        session_key = self.session_table.get_session_key(packet)

        logger.debug(f"Processing packet: {packet.summary()}")

        # Update session information
        if session_key:
            if session_key not in self.session_table.sessions:
                self.total_sessions.inc()
                logger.debug(f"New session detected: {session_key}")

            current_bytes = self.session_table.get(packet, "total_bytes", 0)
            current_packets = self.session_table.get(packet, "total_packets", 0)

            self.session_table.set(packet, "total_bytes", current_bytes + packet_size)
            self.session_table.set(packet, "total_packets", current_packets + 1)

        # Update global statistics
        self.total_bytes.inc(packet_size)
        self.total_packets.inc()

        # Detect anomaly
        is_anomaly, anomaly_type = self.anomaly_detector.detect_anomaly(
            packet, self.session_table.sessions.get(session_key, {})
        )

        if is_anomaly:
            self.anomaly_bytes.inc(packet_size)
            self.anomaly_packets.inc()
            if anomaly_type:
                self.anomaly_type_bytes.labels(type=anomaly_type).inc(packet_size)
                self.anomaly_type_packets.labels(type=anomaly_type).inc()
                logger.debug(f"Anomaly detected: {anomaly_type}")

                # Update session anomaly information and increment counter if it's a new anomaly
                if session_key:
                    session = self.session_table.sessions[session_key]
                    if not session.get("is_anomaly"):
                        session["is_anomaly"] = True
                        session["anomaly_type"] = anomaly_type
                        self.anomaly_sessions.labels(type=anomaly_type).inc()
        else:
            self.normal_bytes.inc(packet_size)
            self.normal_packets.inc()
            logger.debug("Normal packet")

    def start(self):
        # Start Prometheus metrics server
        start_http_server(8000)
        logger.info(f"Started Prometheus metrics server on port 8000")

        # Start packet capture
        logger.info(f"Starting packet capture on interface {self.interface}")
        sniff(iface=self.interface, prn=self.process_packet, store=1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Traffic Monitor with Anomaly Detection"
    )
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface to capture packets from",
    )
    parser.add_argument(
        "-p",
        "--prometheus-port",
        type=int,
        default=8000,
        help="Port for Prometheus metrics server (default: 8000)",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug logging"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Configure logging
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Create and start the traffic monitor with StaticAnomalyDetector
    detector = StaticAnomalyDetector()
    monitor = TrafficMonitor(args.interface, detector)
    monitor.start()


if __name__ == "__main__":
    main()
