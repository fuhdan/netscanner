# Plugin Authoring Guide

`netscanner.py` discovers plugins by scanning `plugins/*.py` at startup.
Each file defines one class inheriting from `ProtocolPlugin`.

---

## Minimal example

Create `plugins/myprotocol.py`:

```python
from netscanner import ProtocolPlugin, ScanResult, STATUS_OPEN

class MyProtocolPlugin(ProtocolPlugin):
    name = "myprotocol"
    default_port = 1234

    def probe(self, sock, ip, cfg, pcap_writers):
        sock.sendall(b"HELLO\r\n")
        data = sock.recv(4096)
        if b"OK" in data:
            return [ScanResult(ip=ip, status=STATUS_OPEN,
                               extra={"greeting": data[:20].decode(errors="replace")})]
        return [ScanResult(ip=ip, status="NO_MYPROTOCOL",
                           detail="unexpected response")]
```

Then run: `python3 netscanner.py 10.0.0.0/24 --protocol myprotocol`

---

## ProtocolPlugin interface

```python
class ProtocolPlugin:
    name: str = ""          # key for --protocol and --list-protocols
    default_port: int = 0   # used when --port is not specified

    def probe(self, sock, ip, cfg, pcap_writers) -> List[ScanResult]:
        raise NotImplementedError
```

---

## Framework guarantees before probe() is called

- TCP connect succeeded within `cfg.connect_timeout`
- A14 check passed (no premature server FIN/RST)
- If `pcap_writers` is not None: SYN, SYN-ACK, ACK frames already written
- Socket is in blocking mode (`settimeout(None)`)
- pcap seq starts at 1/1 post-handshake

---

## Plugin responsibilities

- All protocol-specific send/receive logic
- Writing PSH-ACK pcap frames for data events (if pcap_writers)
- Returning `List[ScanResult]` — one per logical unit or probe attempt
- NOT closing the socket (the framework owns teardown)

The framework closes with RST if any result is non-OPEN, clean FIN if all OPEN.

---

## ScanResult.extra

Use `extra: dict` for protocol-specific fields:

```python
ScanResult(ip=ip, status=STATUS_OPEN, latency_ms=42.0,
           extra={"unit_id": 0, "fc": 3, "register_value": "0x1234"})
```

`format_result_line()` appends `key=value` for each non-None extra entry.
`write_csv()` adds one column per unique extra key across all results.

---

## Writing pcap frames from probe()

Import the TCP flag constants from netscanner:

```python
from netscanner import TCP_PSH_ACK, TCP_RST, TCP_FIN_ACK
```

Track scanner and device sequence numbers starting at 1
(the framework wrote SYN/SYN-ACK/ACK before calling probe()):

```python
_scanner_seq = [1]
_device_seq  = [1]

def _pcap_log(direction, ts, raw_bytes):
    if direction == 'send':
        for w in pcap_writers:
            w.write_packet(ts, local_ip, ip, src_port, cfg.port,
                           TCP_PSH_ACK, _scanner_seq[0], _device_seq[0], raw_bytes)
        _scanner_seq[0] += len(raw_bytes)
    else:
        for w in pcap_writers:
            w.write_packet(ts, ip, local_ip, cfg.port, src_port,
                           TCP_PSH_ACK, _device_seq[0], _scanner_seq[0], raw_bytes)
        _device_seq[0] += len(raw_bytes)
```

Log RST on ZeroWindow/Timeout/OSError. Log FIN-ACK when all results are OPEN
(before returning — the framework's clean_close follows).

---

## Status constants

Generic statuses in `netscanner.py`: `STATUS_OPEN`, `STATUS_REFUSED`,
`STATUS_TIMEOUT_CONNECT`, `STATUS_TIMEOUT_RESPONSE`, `STATUS_ZERO_WINDOW`,
`STATUS_CLOSED_IMMEDIATELY`, `STATUS_NO_PROTOCOL`.

Define protocol-specific statuses in your plugin file:

```python
STATUS_NO_MYPROTOCOL = "NO_MYPROTOCOL"
```

Unknown statuses render in neutral grey in the terminal.

---

## One class per file

Exactly one `ProtocolPlugin` subclass per `.py` file in `plugins/`.
`__init__.py` is skipped. Files are imported in alphabetical order.

---

## Real-world example

See `plugins/modbus.py` — FC3/FC1 probing, dual unit-ID, pcap frame tracking,
ZeroWindow/Timeout/OSError handling.
