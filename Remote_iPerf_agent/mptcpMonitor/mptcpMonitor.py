"""
mptcpMonitor.py
---------------
Monitors per-path throughput for MPTCP connections using eBPF TC classifiers.

Each MPTCP subflow is bound to a specific network interface; by attaching a
BPF TC program to every UP non-loopback interface and filtering on the iPerf
TCP port, we get independent byte counters per path straight from the kernel.

Requirements (system packages, not pip):
    apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
    pip install pyroute2
"""

import os
import socket
import threading
import time
import traceback
from typing import Dict, List, Optional

try:
    from bcc import BPF
    from pyroute2 import IPRoute
    _BPF_AVAILABLE = True
except ImportError:
    _BPF_AVAILABLE = False

# ---------------------------------------------------------------------------
# eBPF program (C) – compiled at runtime by bcc.
# IPERF_PORT is replaced with the actual port number before compilation.
# ---------------------------------------------------------------------------
_BPF_SRC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

/* Map key: (interface index, direction).
   direction 0 = egress (TX), 1 = ingress (RX). */
struct path_key_t {
    u32 ifindex;
    u8  direction;
    u8  pad[3];
};

/* Per-CPU hash avoids atomic contention; Python sums all CPUs on read. */
BPF_PERCPU_HASH(path_bytes, struct path_key_t, u64, 512);

static inline int handle_pkt(struct __sk_buff *skb, u8 direction)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* --- Ethernet -------------------------------------------------------- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* --- IPv4 ------------------------------------------------------------ */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* --- TCP ------------------------------------------------------------- */
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    u16 sport = bpf_ntohs(tcp->source);
    u16 dport = bpf_ntohs(tcp->dest);
    if (sport != IPERF_PORT && dport != IPERF_PORT)
        return TC_ACT_OK;

    /* --- Increment per-CPU counter --------------------------------------- */
    struct path_key_t key = {};
    key.ifindex   = skb->ifindex;
    key.direction = direction;

    u64 zero = 0;
    u64 *total = path_bytes.lookup_or_try_init(&key, &zero);
    if (total)
        *total += (u64)skb->len;

    return TC_ACT_OK;
}

int count_egress(struct __sk_buff *skb)  { return handle_pkt(skb, 0); }
int count_ingress(struct __sk_buff *skb) { return handle_pkt(skb, 1); }
"""

# TC parent handles for clsact qdisc
_TC_EGRESS_PARENT  = "ffff:fff3"   # TC_H_CLSACT | TC_H_MIN_EGRESS
_TC_INGRESS_PARENT = "ffff:fff2"   # TC_H_CLSACT | TC_H_MIN_INGRESS


class MptcpMonitor:
    """
    Attach eBPF TC programs to all UP non-loopback interfaces and collect
    per-interface (= per MPTCP path) byte counters every second.

    Usage::

        monitor = MptcpMonitor(port=5001)
        if monitor.start():
            # ... run iPerf ...
            samples = monitor.stop()   # returns list of per-second samples
    """

    def __init__(self, port: int = 5001):
        self._port = port
        self._bpf: Optional["BPF"] = None
        self._ipr: Optional["IPRoute"] = None
        self._ifaces: List[str] = []
        self._attached_ifindexes: List[int] = []
        self._monitoring = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        # Cumulative byte snapshot at previous sample: {ifindex: {dir: bytes}}
        self._prev_snapshot: Dict[int, Dict[int, int]] = {}
        self._prev_ts: float = 0.0
        # Collected per-second samples
        self._samples: List[Dict] = []

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def start(self) -> bool:
        """
        Load BPF program, attach TC classifiers, start background sampler.
        Returns True on success; False if eBPF is unavailable or setup fails
        (agent continues without per-path data in that case).
        """
        if not _BPF_AVAILABLE:
            print("MptcpMonitor: bcc/pyroute2 not installed – skipping eBPF monitoring")
            return False

        try:
            self._ifaces = _detect_interfaces()
            if not self._ifaces:
                print("MptcpMonitor: neither eth0 nor wwan0 is UP")
                return False

            bpf_src = _BPF_SRC.replace("IPERF_PORT", str(self._port))
            self._bpf = BPF(text=bpf_src)
            fn_egress  = self._bpf.load_func("count_egress",  BPF.SCHED_CLS)
            fn_ingress = self._bpf.load_func("count_ingress", BPF.SCHED_CLS)

            self._ipr = IPRoute()
            for iface in self._ifaces:
                self._attach_to_iface(iface, fn_egress, fn_ingress)

            if not self._attached_ifindexes:
                print("MptcpMonitor: could not attach to any interface")
                self._cleanup()
                return False

            self._prev_ts = time.monotonic()
            self._prev_snapshot = {}
            self._samples = []
            self._monitoring = True
            self._thread = threading.Thread(
                target=self._sample_loop, daemon=True, name="mptcp-monitor"
            )
            self._thread.start()
            print(
                f"MptcpMonitor: running on {self._ifaces} "
                f"monitoring TCP port {self._port}"
            )
            return True

        except Exception as exc:
            print(f"MptcpMonitor: start failed – {exc}")
            traceback.print_exc()
            self._cleanup()
            return False

    def stop(self) -> List[Dict]:
        """
        Stop sampling, detach TC programs, and return the collected samples.

        Each sample has the shape::

            {
                "timestamp": <unix float>,
                "paths": [
                    {"interface": "eth0", "tx_mbps": 45.2, "rx_mbps": 0.1},
                    {"interface": "eth1", "tx_mbps": 32.1, "rx_mbps": 0.0},
                ]
            }
        """
        self._monitoring = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        self._cleanup()
        with self._lock:
            return list(self._samples)

    def get_samples(self) -> List[Dict]:
        """Return a snapshot of samples collected so far (non-destructive)."""
        with self._lock:
            return list(self._samples)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _attach_to_iface(self, iface: str, fn_egress, fn_ingress) -> None:
        links = self._ipr.link_lookup(ifname=iface)
        if not links:
            return
        ifindex = links[0]

        # Add clsact qdisc (TC_H_CLSACT); ignore error if already present
        try:
            self._ipr.tc("add", "clsact", ifindex, "ffff:")
        except Exception:
            pass

        try:
            # Egress filter (handle :1)
            self._ipr.tc(
                "add-filter", "bpf", ifindex, ":1",
                fd=fn_egress.fd, name=fn_egress.name,
                parent=_TC_EGRESS_PARENT, classid=1, direct_action=True,
            )
            # Ingress filter (handle :2)
            self._ipr.tc(
                "add-filter", "bpf", ifindex, ":2",
                fd=fn_ingress.fd, name=fn_ingress.name,
                parent=_TC_INGRESS_PARENT, classid=1, direct_action=True,
            )
            self._attached_ifindexes.append(ifindex)
            print(f"MptcpMonitor: attached to {iface} (ifindex={ifindex})")
        except Exception as exc:
            print(f"MptcpMonitor: failed to attach to {iface}: {exc}")

    def _read_snapshot(self) -> Dict[int, Dict[int, int]]:
        """Read cumulative byte totals from the BPF PERCPU_HASH map."""
        snapshot: Dict[int, Dict[int, int]] = {}
        try:
            for key, per_cpu_values in self._bpf["path_bytes"].items():
                ifindex   = key.ifindex
                direction = key.direction
                total     = sum(per_cpu_values)   # aggregate all CPU buckets
                if ifindex not in snapshot:
                    snapshot[ifindex] = {0: 0, 1: 0}
                snapshot[ifindex][direction] = total
        except Exception as exc:
            print(f"MptcpMonitor: BPF map read error – {exc}")
        return snapshot

    def _sample_loop(self) -> None:
        while self._monitoring:
            time.sleep(1)
            self._take_sample()

    def _take_sample(self) -> None:
        now = time.monotonic()
        dt  = now - self._prev_ts
        if dt <= 0:
            return

        current     = self._read_snapshot()
        sample_paths: List[Dict] = []

        for ifindex in set(self._prev_snapshot) | set(current):
            prev_tx = self._prev_snapshot.get(ifindex, {}).get(0, 0)
            prev_rx = self._prev_snapshot.get(ifindex, {}).get(1, 0)
            curr_tx = current.get(ifindex, {}).get(0, 0)
            curr_rx = current.get(ifindex, {}).get(1, 0)

            delta_tx = max(curr_tx - prev_tx, 0)
            delta_rx = max(curr_rx - prev_rx, 0)

            if delta_tx == 0 and delta_rx == 0:
                continue   # silent interface – skip

            try:
                iface_name = socket.if_indextoname(ifindex)
            except OSError:
                iface_name = f"if{ifindex}"

            sample_paths.append({
                "interface": iface_name,
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

    def _cleanup(self) -> None:
        """Detach TC programs and release BPF/netlink resources."""
        if self._ipr:
            for ifindex in self._attached_ifindexes:
                try:
                    self._ipr.tc("del", "clsact", ifindex, "ffff:")
                except Exception:
                    pass
            try:
                self._ipr.close()
            except Exception:
                pass
            self._ipr = None
        self._attached_ifindexes = []

        if self._bpf:
            try:
                self._bpf.cleanup()
            except Exception:
                pass
            self._bpf = None


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------

_MONITORED_IFACES = ["eth0", "wwan0"]


def _detect_interfaces() -> List[str]:
    """Return whichever of the monitored interfaces are currently UP."""
    ifaces = []
    net_dir = "/sys/class/net"
    for name in _MONITORED_IFACES:
        flags_path = os.path.join(net_dir, name, "flags")
        try:
            with open(flags_path) as fh:
                flags = int(fh.read().strip(), 16)
            if flags & 0x1:   # IFF_UP
                ifaces.append(name)
            else:
                print(f"MptcpMonitor: {name} exists but is not UP, skipping")
        except OSError:
            print(f"MptcpMonitor: {name} not found, skipping")
    return ifaces
