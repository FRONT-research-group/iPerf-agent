"""
mptcpMonitor.py
---------------
Monitors per-path throughput for MPTCP connections by reading per-interface
byte counters from /proc/net/dev every second.

No kernel headers or eBPF required. Counts all traffic on the monitored
interfaces (not filtered by port), which is accurate enough on a dedicated
iPerf test device.
"""

import os
import threading
import time
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MONITORED_IFACES = ["eth0", "wwan0"]


def _iface_is_up(iface: str) -> bool:
    """Return True if the interface exists and is UP."""
    try:
        with open(f"/sys/class/net/{iface}/flags") as fh:
            return bool(int(fh.read().strip(), 16) & 0x1)  # IFF_UP
    except OSError:
        return False


def _detect_interfaces() -> List[str]:
    """Return whichever monitored interfaces are currently UP."""
    return [iface for iface in _MONITORED_IFACES if _iface_is_up(iface)]


def _read_iface_bytes(iface: str) -> Optional[Dict[str, int]]:
    """
    Read cumulative RX/TX byte counters for an interface from /proc/net/dev.
    Returns {'rx': int, 'tx': int} or None if the interface is not found.
    """
    try:
        with open("/proc/net/dev") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith(iface + ":"):
                    continue
                # Fields after colon (space-separated):
                #   0=rx_bytes  1=rx_packets  ...  8=tx_bytes  9=tx_packets ...
                parts = line.split(":")[1].split()
                return {"rx": int(parts[0]), "tx": int(parts[8])}
    except OSError:
        pass
    return None


# ---------------------------------------------------------------------------
# Monitor class
# ---------------------------------------------------------------------------

class MptcpMonitor:
    """
    Sample per-interface byte counters from /proc/net/dev every second and
    convert deltas to Mbps — one sample per second, same shape as the former
    eBPF-based monitor.

    Usage::

        monitor = MptcpMonitor(port=5001)   # port arg kept for API compat
        if monitor.start():
            # ... run iPerf ...
            samples = monitor.stop()
    """

    def __init__(self, port: int = 5001):
        self._port = port          # kept for API compatibility, not used
        self._ifaces: List[str] = []
        self._monitoring = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._prev_snapshot: Dict[str, Dict[str, int]] = {}
        self._prev_ts: float = 0.0
        self._samples: List[Dict] = []

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def start(self) -> bool:
        """
        Detect UP interfaces and start the background sampler.
        Returns True on success, False if no monitored interface is UP.
        """
        self._ifaces = _detect_interfaces()
        if not self._ifaces:
            print("MptcpMonitor: no monitored interface is UP, skipping")
            return False

        self._prev_snapshot = {}
        for iface in self._ifaces:
            counters = _read_iface_bytes(iface)
            if counters:
                self._prev_snapshot[iface] = counters

        self._prev_ts  = time.monotonic()
        self._samples  = []
        self._monitoring = True
        self._thread = threading.Thread(
            target=self._sample_loop, daemon=True, name="mptcp-monitor"
        )
        self._thread.start()
        print(f"MptcpMonitor: running on {self._ifaces} (proc/net/dev counters)")
        return True

    def stop(self) -> List[Dict]:
        """
        Stop sampling and return collected per-second samples.

        Each sample::

            {
                "timestamp": <unix float>,
                "paths": [
                    {"interface": "eth0",  "tx_mbps": 18.3, "rx_mbps": 0.1},
                    {"interface": "wwan0", "tx_mbps":  2.4, "rx_mbps": 0.0},
                ]
            }
        """
        self._monitoring = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        with self._lock:
            return list(self._samples)

    def get_samples(self) -> List[Dict]:
        """Return a snapshot of samples collected so far (non-destructive)."""
        with self._lock:
            return list(self._samples)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _sample_loop(self) -> None:
        while self._monitoring:
            time.sleep(1)
            self._take_sample()

    def _take_sample(self) -> None:
        now = time.monotonic()
        dt  = now - self._prev_ts
        if dt <= 0:
            return

        current: Dict[str, Dict[str, int]] = {}
        sample_paths: List[Dict] = []

        for iface in self._ifaces:
            counters = _read_iface_bytes(iface)
            if counters is None:
                continue
            current[iface] = counters

            prev = self._prev_snapshot.get(iface, {"rx": 0, "tx": 0})
            delta_rx = max(counters["rx"] - prev["rx"], 0)
            delta_tx = max(counters["tx"] - prev["tx"], 0)

            if delta_rx == 0 and delta_tx == 0:
                continue  # silent interface – skip

            sample_paths.append({
                "interface": iface,
                "tx_mbps":   round(delta_tx * 8 / 1e6 / dt, 3),
                "rx_mbps":   round(delta_rx * 8 / 1e6 / dt, 3),
            })

        if sample_paths:
            with self._lock:
                self._samples.append({
                    "timestamp": time.time(),
                    "paths":     sample_paths,
                })

        self._prev_snapshot = current
        self._prev_ts       = now
