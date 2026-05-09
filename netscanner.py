#!/usr/bin/env python3
"""Multi-protocol network scanner framework."""
import argparse
import csv
import errno
import glob
import importlib
import ipaddress
import os
import select
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional

STATUS_OPEN               = "OPEN"
STATUS_REFUSED            = "REFUSED"
STATUS_TIMEOUT_CONNECT    = "TIMEOUT_CONNECT"
STATUS_TIMEOUT_RESPONSE   = "TIMEOUT_RESPONSE"
STATUS_ZERO_WINDOW        = "ZERO_WINDOW"
STATUS_CLOSED_IMMEDIATELY = "CLOSED_IMMEDIATELY"
STATUS_NO_PROTOCOL        = "NO_PROTOCOL"

TCP_SYN     = 0x02
TCP_ACK     = 0x10
TCP_SYN_ACK = 0x12
TCP_PSH_ACK = 0x18
TCP_FIN_ACK = 0x11
TCP_RST     = 0x04


@dataclass
class ScanResult:
    ip: str
    status: str
    latency_ms: float = 0
    detail: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class ScanConfig:
    port: int = 502
    threads: int = 20
    connect_timeout: float = 2.0
    response_timeout: float = 3.0


class ProtocolPlugin:
    name: str = ""
    default_port: int = 0

    def probe(self, _sock: socket.socket, _ip: str, _cfg: "ScanConfig",
              _pcap_writers: Optional[List["PcapWriter"]]) -> List["ScanResult"]:
        raise NotImplementedError


def _discover_plugins() -> dict:
    plugins_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
    # When netscanner.py runs as __main__, plugins may import ProtocolPlugin from
    # the 'netscanner' module (a second import), so collect all known base classes.
    _base_classes: set = {ProtocolPlugin}
    try:
        _ns_mod = importlib.import_module("netscanner")
        _base_classes.add(getattr(_ns_mod, "ProtocolPlugin", ProtocolPlugin))
    except ImportError:
        pass
    result = {}
    for path in sorted(glob.glob(os.path.join(plugins_dir, "*.py"))):
        if os.path.basename(path) == "__init__.py":
            continue
        stem = os.path.splitext(os.path.basename(path))[0]
        mod = importlib.import_module(f"plugins.{stem}")
        for obj in vars(mod).values():
            if (isinstance(obj, type) and
                    any(issubclass(obj, base) for base in _base_classes) and
                    obj not in _base_classes):
                instance = obj()
                result[instance.name] = instance
    return result


def expand_targets(args: List[str], file_path: Optional[str]) -> List[str]:
    raw: List[str] = list(args)
    if file_path:
        try:
            with open(file_path) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw.append(line)
        except OSError as exc:
            print(f"[warn] cannot open file {file_path}: {exc}", file=sys.stderr)
    seen = set()
    result = []
    for entry in raw:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if net.num_addresses == 1:
                ip = str(net.network_address)
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
            else:
                for host in net.hosts():
                    ip = str(host)
                    if ip not in seen:
                        seen.add(ip)
                        result.append(ip)
        except ValueError:
            print(f"[warn] invalid target '{entry}', skipping", file=sys.stderr)
    return result


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _build_raw_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      flags: int, seq: int, ack: int, payload: bytes) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    total_ip_len = 20 + 20 + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s",
                     0x45, 0, total_ip_len, 0, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack(">H", _ip_checksum(ip)) + ip[12:]
    tcp_len = 20 + len(payload)
    tcp = struct.pack(">HHIIBBHHH",
                      src_port, dst_port, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack(">BBH", 0, 6, tcp_len)
    tcp_cksum = _ip_checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack(">H", tcp_cksum) + tcp[18:]
    return ip + tcp + payload


class PcapWriter:
    _GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)

    def __init__(self, path: str) -> None:
        self._lock = threading.Lock()
        self._fh = open(path, "wb")
        try:
            self._fh.write(self._GLOBAL_HEADER)
            self._fh.flush()
        except OSError:
            self._fh.close()
            raise

    def write_packet(self, ts: float, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int, flags: int,
                     seq: int, ack: int, payload: bytes = b"") -> None:
        pkt = _build_raw_packet(src_ip, dst_ip, src_port, dst_port,
                                flags, seq, ack, payload)
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        record = struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)) + pkt
        with self._lock:
            self._fh.write(record)
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except OSError:
                pass


def _rst_close(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _clean_close(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(1.0)
        while True:
            data = sock.recv(4096)
            if not data:
                break
    except (OSError, StopIteration):
        pass
    try:
        sock.close()
    except OSError:
        pass


def _ms(t_start: float) -> float:
    return round((time.monotonic() - t_start) * 1000, 1)


_print_lock = threading.Lock()


def scan_host(ip: str, cfg: ScanConfig, plugin: ProtocolPlugin,
              pcap_writers: Optional[List[PcapWriter]] = None) -> List[ScanResult]:
    results: List[ScanResult] = []
    t_start = time.monotonic()
    local_ip = "0.0.0.0"
    src_port = 0
    _scanner_seq = [0]
    _device_seq  = [0]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(cfg.connect_timeout)
    t_syn = time.time()

    try:
        sock.connect((ip, cfg.port))
    except ConnectionRefusedError:
        _rst_close(sock)
        return [ScanResult(ip=ip, status=STATUS_REFUSED,
                           latency_ms=_ms(t_start), detail="connection refused")]
    except socket.timeout:
        _rst_close(sock)
        return [ScanResult(ip=ip, status=STATUS_TIMEOUT_CONNECT,
                           latency_ms=_ms(t_start), detail="no response to SYN")]
    except OSError as exc:
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
            _rst_close(sock)
            return [ScanResult(ip=ip, status=STATUS_REFUSED,
                               latency_ms=_ms(t_start), detail="host unreachable")]
        _rst_close(sock)
        return [ScanResult(ip=ip, status=STATUS_TIMEOUT_CONNECT,
                           latency_ms=_ms(t_start), detail=f"connect error: {exc}")]

    sock.settimeout(None)

    if pcap_writers:
        local_ip, src_port = sock.getsockname()
        t_connected = time.time()
        for _w in pcap_writers:
            _w.write_packet(t_syn, local_ip, ip, src_port, cfg.port,
                            TCP_SYN, 0, 0)
            _w.write_packet(t_connected, ip, local_ip, cfg.port, src_port,
                            TCP_SYN_ACK, 0, 1)
            _w.write_packet(t_connected, local_ip, ip, src_port, cfg.port,
                            TCP_ACK, 1, 1)
        _scanner_seq[0] = 1
        _device_seq[0]  = 1

    try:
        # 50ms window: detect servers that FIN/RST immediately after handshake (A14)
        readable, _, _ = select.select([sock], [], [], 0.05)
        if readable:
            data = sock.recv(1024)
            if not data:
                if pcap_writers:
                    t_fin = time.time()
                    for _w in pcap_writers:
                        _w.write_packet(t_fin, ip, local_ip, cfg.port, src_port,
                                        TCP_FIN_ACK, _device_seq[0], _scanner_seq[0])
                _rst_close(sock)
                return [ScanResult(ip=ip, status=STATUS_CLOSED_IMMEDIATELY,
                                   latency_ms=_ms(t_start),
                                   detail="server FIN immediately after handshake")]
            _rst_close(sock)
            return [ScanResult(ip=ip, status=STATUS_NO_PROTOCOL,
                               latency_ms=_ms(t_start),
                               detail="unexpected data before request")]
    except OSError:
        _rst_close(sock)
        return [ScanResult(ip=ip, status=STATUS_CLOSED_IMMEDIATELY,
                           latency_ms=_ms(t_start),
                           detail="server RST immediately after handshake")]

    try:
        results = plugin.probe(sock, ip, cfg, pcap_writers)
    except Exception as exc:
        _rst_close(sock)
        return [ScanResult(ip=ip, status=STATUS_NO_PROTOCOL,
                           latency_ms=_ms(t_start), detail=str(exc))]

    if all(r.status == STATUS_OPEN for r in results):
        _clean_close(sock)
    else:
        _rst_close(sock)
    return results


def run_scan(targets: List[str], cfg: ScanConfig, plugin: ProtocolPlugin,
             print_result_fn=None,
             pcap_dir: Optional[str] = None) -> List[ScanResult]:
    if not targets:
        return []

    combined_writer: Optional[PcapWriter] = None
    host_writers: dict = {}

    if pcap_dir:
        try:
            os.makedirs(pcap_dir, exist_ok=True)
        except OSError as exc:
            print(f"[warn] cannot create pcap directory {pcap_dir}: {exc}",
                  file=sys.stderr)
            pcap_dir = None

    if pcap_dir:
        ts_str = time.strftime("%Y%m%d_%H%M%S")
        combined_path = os.path.join(pcap_dir, f"scan_{ts_str}.pcap")
        try:
            combined_writer = PcapWriter(combined_path)
        except OSError as exc:
            print(f"[warn] cannot create {combined_path}: {exc}", file=sys.stderr)

        for ip in targets:
            host_path = os.path.join(pcap_dir, f"{ip}.pcap")
            try:
                host_writers[ip] = PcapWriter(host_path)
            except OSError as exc:
                print(f"[warn] cannot create {host_path}: {exc}", file=sys.stderr)

    all_results: List[ScanResult] = []

    with ThreadPoolExecutor(max_workers=cfg.threads) as executor:
        futures: dict = {}
        future_host_writer: dict = {}

        for ip in targets:
            writers = []
            hw = host_writers.get(ip)
            if hw:
                writers.append(hw)
            if combined_writer:
                writers.append(combined_writer)
            fut = executor.submit(scan_host, ip, cfg, plugin,
                                  writers if writers else None)
            futures[fut] = ip
            future_host_writer[fut] = hw

        for future in as_completed(futures):
            ip = futures[future]
            try:
                host_results = future.result()
            except Exception as exc:
                host_results = [ScanResult(ip=ip, status=STATUS_NO_PROTOCOL,
                                           detail=str(exc))]
            hw = future_host_writer.get(future)
            if hw:
                hw.close()
            for r in host_results:
                all_results.append(r)
                if print_result_fn:
                    with _print_lock:
                        print_result_fn(r)

    if combined_writer:
        combined_writer.close()
    return all_results


_ANSI = {
    "green":   "\033[92m",
    "yellow":  "\033[93m",
    "red":     "\033[91m",
    "magenta": "\033[95m",
    "grey":    "\033[90m",
    "reset":   "\033[0m",
    "bold":    "\033[1m",
}

_STATUS_COLOR = {
    STATUS_OPEN:               "green",
    STATUS_CLOSED_IMMEDIATELY: "magenta",
    STATUS_ZERO_WINDOW:        "magenta",
    STATUS_REFUSED:            "red",
    STATUS_TIMEOUT_CONNECT:    "grey",
    STATUS_TIMEOUT_RESPONSE:   "grey",
    STATUS_NO_PROTOCOL:        "grey",
}


def _colorize(text: str, color: str) -> str:
    return f"{_ANSI[color]}{text}{_ANSI['reset']}"


def format_result_line(result: ScanResult, color: bool = True) -> str:
    ip_col = f"[{result.ip}]".ljust(20)
    status_col = result.status.ljust(22)
    if color:
        c = _STATUS_COLOR.get(result.status, "reset")
        status_col = _colorize(status_col, c)
    parts = [ip_col, status_col]
    if result.extra:
        for k, v in result.extra.items():
            if v is not None:
                parts.append(f"{k}={v}")
    elif result.detail:
        parts.append(result.detail)
    parts.append(f"{result.latency_ms:.0f}ms")
    return "  ".join(p for p in parts if p.strip())


def format_summary(results: List[ScanResult], duration: float,
                   cfg: ScanConfig) -> str:
    from collections import Counter
    status_counts: Counter = Counter(r.status for r in results)
    w = 54
    bar = "═" * w
    lines = [
        f"\n{bar}",
        " SCAN SUMMARY".center(w),
        bar,
        f"  Targets scanned  : {len(set(r.ip for r in results))}",
        f"  Duration         : {duration:.1f}s   Threads: {cfg.threads}",
        f"  Port             : {cfg.port}",
        "",
        "  Results:",
    ]
    for status, count in sorted(status_counts.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"    {status:<24}: {count:>4}")
    lines.append(bar)
    return "\n".join(lines)


def write_csv(results: List[ScanResult], fileobj) -> None:
    extra_keys: List[str] = []
    for r in results:
        for k in r.extra:
            if k not in extra_keys:
                extra_keys.append(k)
    writer = csv.writer(fileobj)
    writer.writerow(["ip", "status", "latency_ms", "detail"] + extra_keys)
    for r in results:
        row = [r.ip, r.status, r.latency_ms, r.detail]
        for k in extra_keys:
            row.append(r.extra.get(k, ""))
        writer.writerow(row)


def _pick_plugin_interactive(plugins: dict) -> ProtocolPlugin:
    names = list(plugins.keys())
    print("Select protocol:")
    for i, name in enumerate(names, 1):
        p = plugins[name]
        print(f"  [{i}] {name:<12} (port {p.default_port})")
    while True:
        try:
            choice = input("> ").strip()
        except EOFError:
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(names):
                return plugins[names[idx]]
        except ValueError:
            pass
        print(f"Enter a number between 1 and {len(names)}")
    raise SystemExit("no protocol selected")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-protocol network scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*",
                        help="IPs and/or CIDR ranges (e.g. 10.0.0.1 10.0.0.0/24)")
    parser.add_argument("--file", "-f", metavar="FILE",
                        help="text file with one IP or CIDR per line")
    parser.add_argument("--protocol", metavar="NAME",
                        help="protocol plugin to use (see --list-protocols)")
    parser.add_argument("--list-protocols", action="store_true",
                        help="list available protocol plugins and exit")
    parser.add_argument("--threads", type=int, default=20, metavar="N",
                        help="number of concurrent scanner threads (default: 20)")
    parser.add_argument("--connect-timeout", type=float, default=2.0, metavar="S",
                        help="TCP connect timeout in seconds (default: 2.0)")
    parser.add_argument("--response-timeout", type=float, default=3.0, metavar="S",
                        help="response timeout in seconds (default: 3.0)")
    parser.add_argument("--port", type=int, default=0,
                        help="override protocol default port")
    parser.add_argument("--output", metavar="FILE",
                        help="write CSV results to FILE")
    parser.add_argument("--pcap-dir", metavar="DIR",
                        help="write per-host and combined .pcap captures to DIR "
                             "(created if it does not exist)")
    args = parser.parse_args()

    plugins = _discover_plugins()

    if args.list_protocols:
        for name, p in plugins.items():
            print(f"  {name:<12} (port {p.default_port})")
        return

    if args.protocol:
        if args.protocol not in plugins:
            parser.error(f"unknown protocol '{args.protocol}'. "
                         f"Available: {', '.join(plugins)}")
        plugin = plugins[args.protocol]
    elif sys.stdout.isatty() and plugins:
        plugin = _pick_plugin_interactive(plugins)
    else:
        parser.error("--protocol is required. Use --list-protocols to see options.")

    port = args.port if args.port else plugin.default_port
    cfg = ScanConfig(port=port, threads=args.threads,
                     connect_timeout=args.connect_timeout,
                     response_timeout=args.response_timeout)

    targets = expand_targets(args.targets, file_path=args.file)
    if not targets:
        parser.error("no targets specified — provide IPs/CIDRs as arguments or via --file")

    use_color = sys.stdout.isatty()
    print(f"Scanning {len(targets)} host(s) on port {cfg.port} "
          f"with {cfg.threads} threads…")

    t_start = time.monotonic()
    results = run_scan(
        targets, cfg, plugin,
        print_result_fn=lambda r: print(format_result_line(r, color=use_color)),
        pcap_dir=args.pcap_dir,
    )
    duration = time.monotonic() - t_start
    print(format_summary(results, duration=duration, cfg=cfg))

    if args.output:
        try:
            with open(args.output, "w", newline="") as fh:
                write_csv(results, fh)
            print(f"\nResults saved to {args.output}")
        except OSError as exc:
            print(f"[error] could not write {args.output}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[interrupted] partial results above", file=sys.stderr)
        sys.exit(1)
