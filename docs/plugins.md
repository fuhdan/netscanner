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
- The connection survived a 50 ms read window: a server that sent a FIN, reset,
  or spoke before being asked was already reported and never reaches `probe()`
- If `pcap_writers` is not None: SYN, SYN-ACK, ACK frames already written
- The socket carries a timeout of `cfg.response_timeout`, so a `recv` or
  `sendall` you forget to guard raises rather than holding a worker thread for
  the rest of the scan. Guard them anyway — `select` lets you tell a stalled
  receive window apart from a silent peer, and those are different findings
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

## ProbeChannel — the socket work you should not write yourself

Three things are the same in every plugin: telling a stalled receive window
apart from a silent peer, writing the capture frames, and keeping the two
sequence numbers straight. `ProbeChannel` does all three.

```python
from netscanner import ProbeChannel, ZeroWindowError

def probe(self, sock, ip, cfg, pcap_writers):
    channel = ProbeChannel(sock, ip, cfg, pcap_writers)
    try:
        reply = channel.exchange(build_request())
    except ZeroWindowError:
        channel.note_reset()
        return [ScanResult(ip=ip, status=STATUS_ZERO_WINDOW,
                           detail="TCP ZeroWindow on send")]
    except TimeoutError:
        channel.note_reset()
        return [ScanResult(ip=ip, status=STATUS_TIMEOUT_RESPONSE,
                           detail="no response within timeout")]
    except OSError as exc:
        channel.note_reset(from_scanner=False)
        return [ScanResult(ip=ip, status="NO_MYPROTOCOL", detail=str(exc))]

    channel.note_finished()
    return [ScanResult(ip=ip, status=STATUS_OPEN, extra=parse(reply))]
```

| | |
|---|---|
| `send(payload)` | sends under `cfg.response_timeout`; raises `ZeroWindowError` if the peer will not take it |
| `recv(bufsize=4096)` | reads one response; raises `TimeoutError` on silence, `OSError` if the peer closed |
| `exchange(payload, bufsize=4096)` | one request, one response |
| `note_reset(from_scanner=True)` | record that the exchange ended in a reset — pass `False` when the device reset us |
| `note_finished()` | record a clean finish; call it before returning all-`OPEN` results |

Every method is a no-op on the capture side when `pcap_writers` is `None`, so
the same code works with and without `--pcap-dir`. Sequence numbers start at 1
on both sides and advance by payload length, which is what makes Wireshark read
the file as one conversation.

The socket is still yours: a protocol that needs something the channel does not
offer can use it directly, and write frames itself with
`PcapWriter.write_packet` and the `TCP_*` flag constants from `netscanner`.

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

Discovery is defensive: a file that raises on import, a class that raises when
constructed, and a class with no `name` are each reported on stderr and skipped,
so one bad plugin costs that plugin and not the scan. A `name` already taken by
an earlier plugin is refused rather than silently overwriting it — pick a name
no other plugin uses.

---

## Real-world example

See `plugins/modbus.py` — FC3/FC1 probing, dual unit-ID, pcap frame tracking,
ZeroWindow/Timeout/OSError handling.
