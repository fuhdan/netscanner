import io
import os
import socket
import struct
import tempfile
import threading

import pytest
from unittest.mock import MagicMock, patch

from netscanner import (
    ScanResult, ScanConfig, ProtocolPlugin,
    PcapWriter, TCP_SYN, TCP_ACK, TCP_SYN_ACK,
    TCP_PSH_ACK, TCP_FIN_ACK, TCP_RST, _ip_checksum,
    expand_targets,
    STATUS_OPEN, STATUS_REFUSED, STATUS_TIMEOUT_CONNECT,
    STATUS_TIMEOUT_RESPONSE, STATUS_ZERO_WINDOW,
    STATUS_CLOSED_IMMEDIATELY, STATUS_NO_PROTOCOL,
    scan_host, run_scan, format_result_line, format_summary, write_csv,
)


def test_scan_result_defaults():
    r = ScanResult(ip="10.0.0.1", status="OPEN")
    assert r.latency_ms == 0
    assert r.detail == ""
    assert r.extra == {}


def test_scan_result_extra_dict():
    r = ScanResult(ip="10.0.0.1", status=STATUS_OPEN,
                   extra={"unit_id": 0, "fc": 3, "register_value": "0x1234"})
    assert r.extra["unit_id"] == 0
    assert r.extra["register_value"] == "0x1234"


def test_scan_result_extra_default_factory():
    r1 = ScanResult(ip="10.0.0.1", status=STATUS_OPEN)
    r2 = ScanResult(ip="10.0.0.2", status=STATUS_OPEN)
    r1.extra["x"] = 1
    assert "x" not in r2.extra


def test_scan_config_defaults():
    cfg = ScanConfig()
    assert cfg.port == 502
    assert cfg.threads == 20
    assert cfg.connect_timeout == 2.0
    assert cfg.response_timeout == 3.0


def test_protocol_plugin_probe_raises():
    class BrokenPlugin(ProtocolPlugin):
        name = "broken"
        default_port = 1234
    p = BrokenPlugin()
    with pytest.raises(NotImplementedError):
        p.probe(MagicMock(), "10.0.0.1", ScanConfig(), None)


def test_expand_single_ip():
    assert expand_targets(["10.0.0.1"], file_path=None) == ["10.0.0.1"]


def test_expand_cidr():
    result = expand_targets(["10.0.0.0/30"], file_path=None)
    assert "10.0.0.1" in result
    assert "10.0.0.2" in result
    assert "10.0.0.0" not in result
    assert len(result) == 2


def test_deduplication():
    result = expand_targets(["10.0.0.1", "10.0.0.1"], file_path=None)
    assert result.count("10.0.0.1") == 1


def test_expand_from_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("10.0.0.5\n# comment\n\n10.0.0.10\n")
        fname = f.name
    try:
        result = expand_targets([], file_path=fname)
        assert "10.0.0.5" in result
        assert "10.0.0.10" in result
    finally:
        os.unlink(fname)


def test_invalid_target_skipped(capsys):
    result = expand_targets(["not-an-ip"], file_path=None)
    assert result == []
    assert "not-an-ip" in capsys.readouterr().err


def _parse_pcap_records(data: bytes):
    records = []
    pos = 24
    while pos + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _ = struct.unpack("<IIII", data[pos:pos + 16])
        pkt = data[pos + 16: pos + 16 + incl_len]
        records.append((ts_sec + ts_usec / 1_000_000, pkt))
        pos += 16 + incl_len
    return records


def _pkt_tcp_flags(pkt: bytes) -> int:
    return pkt[33]


def _pkt_payload(pkt: bytes) -> bytes:
    return pkt[40:]


def test_pcap_writer_global_header():
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        w.close()
        with open(path, 'rb') as f:
            data = f.read()
        assert len(data) == 24
        magic, vmaj, vmin, tz, acc, snaplen, network = struct.unpack("<IHHiIII", data)
        assert magic == 0xa1b2c3d4
        assert vmaj == 2 and vmin == 4
        assert snaplen == 65535
        assert network == 101
    finally:
        os.unlink(path)


def test_pcap_writer_single_packet():
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        payload = b'\x00\x01\x00\x00\x00\x06\x00\x03\x00\x00\x00\x01'
        w = PcapWriter(path)
        w.write_packet(1000.5, '10.0.0.1', '10.0.0.2', 12345, 502,
                       TCP_PSH_ACK, 1, 1, payload)
        w.close()
        with open(path, 'rb') as f:
            data = f.read()
        assert len(data) == 24 + 16 + 20 + 20 + len(payload)
        records = _parse_pcap_records(data)
        assert len(records) == 1
        ts, pkt = records[0]
        assert abs(ts - 1000.5) < 0.001
        assert pkt[0] == 0x45
        assert pkt[9] == 6
        assert socket.inet_ntoa(pkt[12:16]) == '10.0.0.1'
        sport, dport = struct.unpack(">HH", pkt[20:24])
        assert sport == 12345 and dport == 502
        assert _pkt_tcp_flags(pkt) == TCP_PSH_ACK
        assert _pkt_payload(pkt) == payload
    finally:
        os.unlink(path)


def test_pcap_writer_checksum():
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        payload = b'\x01\x02\x03\x04'
        w = PcapWriter(path)
        w.write_packet(0.0, '192.168.1.1', '192.168.1.2', 9999, 502,
                       TCP_PSH_ACK, 100, 200, payload)
        w.close()
        with open(path, 'rb') as f:
            raw = f.read()
        pkt = raw[40:]
        ip_hdr = pkt[:20]
        stored_ip = struct.unpack(">H", ip_hdr[10:12])[0]
        zeroed_ip = ip_hdr[:10] + b'\x00\x00' + ip_hdr[12:]
        assert _ip_checksum(zeroed_ip) == stored_ip
        tcp_hdr = pkt[20:40]
        stored_tcp = struct.unpack(">H", tcp_hdr[16:18])[0]
        pseudo = pkt[12:16] + pkt[16:20] + struct.pack(">BBH", 0, 6, 20 + len(payload))
        zeroed_tcp = tcp_hdr[:16] + b'\x00\x00' + tcp_hdr[18:]
        assert _ip_checksum(pseudo + zeroed_tcp + payload) == stored_tcp
    finally:
        os.unlink(path)


def test_pcap_writer_thread_safety():
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        threads = [
            threading.Thread(target=lambda wtr=w: [
                wtr.write_packet(1.0, '1.2.3.4', '5.6.7.8', 1234, 502, TCP_ACK, 0, 0)
                for _ in range(10)
            ])
            for _ in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        w.close()
        with open(path, 'rb') as f:
            data = f.read()
        assert len(data) == 24 + 500 * (16 + 40)
        records = _parse_pcap_records(data)
        assert len(records) == 500
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# FakePlugin
# ---------------------------------------------------------------------------

class FakePlugin(ProtocolPlugin):
    name = "fake"
    default_port = 9999

    def probe(self, sock, ip, cfg, pcap_writers):
        return [ScanResult(ip=ip, status=STATUS_OPEN)]


# ---------------------------------------------------------------------------
# scan_host connection-level paths
# ---------------------------------------------------------------------------

@patch("netscanner.socket.socket")
def test_scan_host_refused(mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.connect.side_effect = ConnectionRefusedError()
    results = scan_host("10.0.0.1", ScanConfig(port=9999), FakePlugin())
    assert results[0].status == STATUS_REFUSED


@patch("netscanner.socket.socket")
def test_scan_host_timeout_connect(mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.connect.side_effect = socket.timeout()
    results = scan_host("10.0.0.1", ScanConfig(port=9999), FakePlugin())
    assert results[0].status == STATUS_TIMEOUT_CONNECT


@patch("netscanner.socket.socket")
@patch("netscanner.select.select")
def test_scan_host_closed_immediately_a14(mock_ns_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    mock_ns_select.return_value = ([sock], [], [])
    sock.recv.return_value = b""
    results = scan_host("10.0.0.1", ScanConfig(port=9999), FakePlugin())
    assert results[0].status == STATUS_CLOSED_IMMEDIATELY


@patch("netscanner.socket.socket")
@patch("netscanner.select.select")
def test_scan_host_delegates_to_plugin(mock_ns_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.return_value = ([], [], [])
    # _clean_close drains the socket; return b"" so the loop exits
    sock.recv.return_value = b""
    results = scan_host("10.0.0.1", ScanConfig(port=9999), FakePlugin())
    assert results[0].status == STATUS_OPEN


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------

def test_run_scan_returns_all_results():
    cfg = ScanConfig(threads=2)

    def fake_scan(ip, cfg, plugin, pcap_writers=None):
        return [ScanResult(ip=ip, status=STATUS_REFUSED)]

    with patch("netscanner.scan_host", side_effect=fake_scan):
        results = run_scan(["10.0.0.1", "10.0.0.2"], cfg, FakePlugin())

    assert {r.ip for r in results} == {"10.0.0.1", "10.0.0.2"}


def test_run_scan_empty_targets():
    assert run_scan([], ScanConfig(), FakePlugin()) == []


def test_run_scan_flattens_multiple_results():
    def fake_scan(ip, cfg, plugin, pcap_writers=None):
        return [ScanResult(ip=ip, status=STATUS_OPEN, extra={"unit_id": 0}),
                ScanResult(ip=ip, status=STATUS_OPEN, extra={"unit_id": 1})]

    with patch("netscanner.scan_host", side_effect=fake_scan):
        results = run_scan(["10.0.0.1"], ScanConfig(threads=1), FakePlugin())

    assert len(results) == 2
    assert sorted(r.extra["unit_id"] for r in results) == [0, 1]


def test_run_scan_exception_returns_no_protocol():
    with patch("netscanner.scan_host", side_effect=RuntimeError("boom")):
        results = run_scan(["10.0.0.9"], ScanConfig(threads=1), FakePlugin())
    assert results[0].status == STATUS_NO_PROTOCOL
    assert "boom" in results[0].detail


def test_run_scan_pcap_dir_creates_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        def fake_scan(ip, cfg, plugin, pcap_writers=None):
            return [ScanResult(ip=ip, status=STATUS_REFUSED)]

        with patch("netscanner.scan_host", side_effect=fake_scan):
            run_scan(["10.0.0.1", "10.0.0.2"], ScanConfig(threads=1),
                     FakePlugin(), pcap_dir=tmpdir)

        files = os.listdir(tmpdir)
        combined = [f for f in files if f.startswith("scan_") and f.endswith(".pcap")]
        assert len(combined) == 1
        assert "10.0.0.1.pcap" in files and "10.0.0.2.pcap" in files
        with open(os.path.join(tmpdir, combined[0]), 'rb') as fh:
            magic = struct.unpack("<I", fh.read(4))[0]
        assert magic == 0xa1b2c3d4


def test_run_scan_pcap_dir_unwritable_warns(capsys):
    bad_dir = "/nonexistent_root_xyz/cannot_create"

    def fake_scan(ip, cfg, plugin, pcap_writers=None):
        return [ScanResult(ip=ip, status=STATUS_REFUSED)]

    with patch("netscanner.scan_host", side_effect=fake_scan):
        results = run_scan(["10.0.0.1"], ScanConfig(threads=1), FakePlugin(),
                           pcap_dir=bad_dir)
    assert results[0].status == STATUS_REFUSED
    assert bad_dir in capsys.readouterr().err


# ---------------------------------------------------------------------------
# format_result_line
# ---------------------------------------------------------------------------

def test_format_result_line_open_with_extra():
    r = ScanResult(ip="10.0.0.1", status=STATUS_OPEN, latency_ms=42.0,
                   extra={"unit_id": 0, "fc": 3, "register_value": "0x1234"})
    line = format_result_line(r, color=False)
    assert "10.0.0.1" in line
    assert "OPEN" in line
    assert "unit_id=0" in line
    assert "register_value=0x1234" in line
    assert "42" in line


def test_format_result_line_detail_when_no_extra():
    r = ScanResult(ip="10.0.0.2", status=STATUS_CLOSED_IMMEDIATELY,
                   latency_ms=1.0, detail="server FIN immediately after handshake")
    line = format_result_line(r, color=False)
    assert "CLOSED_IMMEDIATELY" in line
    assert "server FIN" in line


def test_format_result_line_none_extra_values_skipped():
    r = ScanResult(ip="10.0.0.1", status=STATUS_OPEN, latency_ms=10.0,
                   extra={"unit_id": 0, "register_value": None})
    line = format_result_line(r, color=False)
    assert "unit_id=0" in line
    assert "register_value" not in line


# ---------------------------------------------------------------------------
# format_summary
# ---------------------------------------------------------------------------

def test_format_summary_counts():
    results = [
        ScanResult(ip="10.0.0.1", status=STATUS_OPEN),
        ScanResult(ip="10.0.0.2", status=STATUS_OPEN),
        ScanResult(ip="10.0.0.3", status=STATUS_REFUSED),
        ScanResult(ip="10.0.0.4", status=STATUS_CLOSED_IMMEDIATELY),
    ]
    summary = format_summary(results, duration=5.0, cfg=ScanConfig())
    assert "OPEN" in summary
    assert "REFUSED" in summary
    assert "CLOSED_IMMEDIATELY" in summary
    assert "FC3" not in summary   # generic — no FC breakdown


def test_format_summary_unique_ip_count():
    results = [
        ScanResult(ip="10.0.0.1", status=STATUS_OPEN),
        ScanResult(ip="10.0.0.1", status=STATUS_OPEN, extra={"unit_id": 1}),
    ]
    summary = format_summary(results, duration=1.0, cfg=ScanConfig())
    assert "Targets scanned  : 1" in summary


# ---------------------------------------------------------------------------
# write_csv
# ---------------------------------------------------------------------------

def test_write_csv_generic_extra_columns():
    results = [
        ScanResult(ip="10.0.0.1", status=STATUS_OPEN, latency_ms=42.0,
                   extra={"unit_id": 0, "fc": 3, "register_value": "0x1234"}),
        ScanResult(ip="10.0.0.2", status=STATUS_CLOSED_IMMEDIATELY,
                   latency_ms=1.0, detail="server FIN immediately after handshake"),
    ]
    buf = io.StringIO()
    write_csv(results, buf)
    buf.seek(0)
    content = buf.read()
    assert "ip,status,latency_ms,detail,unit_id,fc,register_value" in content
    assert "0x1234" in content
    assert "CLOSED_IMMEDIATELY" in content


def test_write_csv_missing_extra_empty():
    results = [
        ScanResult(ip="10.0.0.1", status=STATUS_OPEN,
                   extra={"unit_id": 0, "fc": 3}),
        ScanResult(ip="10.0.0.2", status=STATUS_REFUSED),
    ]
    buf = io.StringIO()
    write_csv(results, buf)
    buf.seek(0)
    lines = buf.read().strip().split("\n")
    assert "unit_id" in lines[0]
    row2 = lines[2].split(",")
    assert row2[0] == "10.0.0.2"
