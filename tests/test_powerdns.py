"""Policy bridge tests; the live Recursor test runs when pdns_recursor is installed."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import dns.message
import dns.query
import dns.rcode
import dns.rrset
import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("powerdns_bridge", ROOT / "bridge.py")
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)
KEY = "powerdns-test-policy-key-123456789"


def packet(name="example.com.", ip="192.0.2.3", qtype=1, protocol="udp"):
    return f"v1\n{ip}\n12345\n{protocol}\n{qtype}\n{name.encode().hex()}".encode()


def test_metadata():
    payload = bridge.decode_query(packet(qtype=28, ip="2001:db8::1", protocol="tcp"), "recursor-1")
    assert payload == {"server_id": "recursor-1", "protocol": "tcp",
                       "client": {"ip": "2001:db8::1", "port": 12345},
                       "dns": {"questions": [{"name": "example.com.", "type": "AAAA", "class": "IN"}]}}
    assert bridge.decode_query(packet(qtype=65400), "p")["dns"]["questions"][0]["type"] == "TYPE65400"


@pytest.mark.parametrize("value", [b"", b"x" * 4097, packet(ip="invalid"), packet(qtype=65536),
                                    packet(protocol="http"), packet(name="bad\nname")])
def test_invalid_packets(value):
    with pytest.raises(ValueError):
        bridge.decode_query(value, "p")


@pytest.mark.parametrize("mode", ["nxdomain", "refused", "nodata", "zero"])
def test_decisions(mode):
    assert bridge.decode_decision(json.dumps({"block": True, "response_mode": mode})) == mode.encode()
    assert bridge.decode_decision('{"block":false}') == b"allow"


@pytest.mark.parametrize("body", ['null', '[]', '{"block":"false"}', '{"block":1}',
                                  '{"block":true}', '{"block":true,"response_mode":[]}', '{"block":true,"response_mode":"bogus"}'])
def test_invalid_decisions(body):
    with pytest.raises(ValueError):
        bridge.decode_decision(body)


@pytest.mark.parametrize("change", [{"endpoint": "https://user:key@example.com/api/v1/decision"},
    {"endpoint": "file:///api/v1/decision"}, {"api_key": "short"}, {"timeout": float("nan")},
    {"timeout": 0}, {"timeout": 2}, {"max_inflight": 0}, {"port": 70000}])
def test_invalid_config(change):
    values = {"endpoint": "https://example.com/api/v1/decision", "api_key": KEY}
    values.update(change)
    with pytest.raises(ValueError):
        bridge.Config(**values)


class Transport:
    def __init__(self):
        self.answers = []
        self.closed = False

    def sendto(self, data, address):
        self.answers.append((data, address))

    def is_closing(self):
        return self.closed

    def close(self):
        self.closed = True


def test_http_errors_timeout_and_concurrency():
    async def run():
        requests = []

        async def handler(request):
            requests.append(request)
            name = json.loads(request.content)["dns"]["questions"][0]["name"]
            if name == "slow.":
                await asyncio.sleep(1)
            if name == "large.":
                return httpx.Response(200, content=b"x" * 20000)
            if name == "auth.":
                return httpx.Response(401)
            if name == "redirect.":
                return httpx.Response(302, headers={"Location": "https://other.example/"})
            return httpx.Response(200, json={"block": False})

        config = bridge.Config("https://policy.example/api/v1/decision", KEY, timeout=0.01, max_inflight=1)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            service = bridge.Bridge(config, client)
            transport = Transport()
            service.connection_made(transport)
            address = ("127.0.0.1", 1234)
            for name in ("allow.", "auth.", "redirect.", "large.", "slow."):
                await service.respond(bridge.decode_query(packet(name), "p"), address)
            assert [a[0] for a in transport.answers] == [b"allow"] + [b"error"] * 4
            assert service.failed == 4
            assert all(r.headers["X-API-Key"] == KEY for r in requests)
            service.datagram_received(packet("slow."), address)
            service.datagram_received(packet(), address)
            assert service.overloaded == 1
            assert len(service.tasks) == 1
            before = len(transport.answers)
            service.datagram_received(packet(), ("192.0.2.3", 1234))
            assert len(transport.answers) == before
            await service.close()
            assert not service.tasks
    asyncio.run(run())


def free_port(kind=socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.skipif(not shutil.which("pdns_recursor"), reason="requires PowerDNS Recursor")
@pytest.mark.parametrize("fail_mode", ["open", "closed"])
def test_live_recursor(tmp_path, fail_mode):
    """Real UDP/TCP DNS -> Lua -> bridge -> HTTP -> DNS, without public DNS."""
    state = {"mode": "allow", "requests": []}

    class Policy(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.headers.get("X-API-Key") == KEY
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append(payload)
            mode = state["mode"]
            if mode == "error":
                self.send_response(503)
                self.end_headers()
                return
            if mode == "client":
                mode = "nxdomain" if payload["client"]["ip"] == "127.0.0.2" else "allow"
            body = json.dumps({"block": mode != "allow", "response_mode": mode}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    policy = ThreadingHTTPServer(("127.0.0.1", 0), Policy)
    threading.Thread(target=policy.serve_forever, daemon=True).start()
    authority = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    authority.bind(("127.0.0.1", 0))
    authority.settimeout(0.1)
    stopped = threading.Event()

    def answer_dns():
        while not stopped.is_set():
            try:
                data, address = authority.recvfrom(4096)
            except socket.timeout:
                continue
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            response.answer.append(dns.rrset.from_text(request.question[0].name, 300, "IN", "A", "192.0.2.123"))
            authority.sendto(response.to_wire(), address)

    dns_thread = threading.Thread(target=answer_dns, daemon=True)
    dns_thread.start()
    bridge_port, recursor_port = free_port(), free_port()
    lua = (ROOT / "blockinator.lua").read_text()
    lua = lua.replace("127.0.0.1:53001", f"127.0.0.1:{bridge_port}")
    lua = lua.replace('local failMode = "open"', f'local failMode = "{fail_mode}"')
    (tmp_path / "blockinator.lua").write_text(lua)
    (tmp_path / "recursor.conf").write_text(
        f"local-address=127.0.0.1\nlocal-port={recursor_port}\nallow-from=127.0.0.0/8\n"
        f"lua-dns-script={tmp_path}/blockinator.lua\n"
        f"forward-zones-recurse=.=127.0.0.1:{authority.getsockname()[1]}\n"
        "dnssec=off\nsecurity-poll-suffix=\n")
    env = dict(os.environ, BLOCKINATOR_ENDPOINT=f"http://127.0.0.1:{policy.server_port}/api/v1/decision",
               POLICY_API_KEY=KEY, POWERDNS_BRIDGE_PORT=str(bridge_port), POWERDNS_TIMEOUT_MS="100")
    processes = []
    logs = []
    try:
        for command in ([sys.executable, str(ROOT / "bridge.py")],
                        ["pdns_recursor", f"--config-dir={tmp_path}", f"--socket-dir={tmp_path}",
                         "--daemon=no", "--write-pid=no", "--disable-syslog=yes"]):
            log = open(tmp_path / f"process-{len(logs)}.log", "w+")
            logs.append(log)
            processes.append(subprocess.Popen(command, env=env, stdout=log, stderr=log))

        def query(qtype="A", tcp=False, source="127.0.0.1"):
            request = dns.message.make_query("policy.example.", qtype)
            return (dns.query.tcp if tcp else dns.query.udp)(
                request, "127.0.0.1", port=recursor_port, source=source, timeout=3)

        for _ in range(50):
            if any(p.poll() is not None for p in processes):
                pytest.fail("Process exited: " + "\n".join(Path(f.name).read_text() for f in logs))
            try:
                result = query()
                if state["requests"]:
                    break
            except (dns.exception.Timeout, OSError):
                pass
            time.sleep(0.1)
        else:
            pytest.fail("Recursor/bridge did not become ready")
        assert result.answer[0][0].address == "192.0.2.123"
        for mode, code in (("nxdomain", 3), ("refused", 5), ("nodata", 0)):
            state["mode"] = mode
            for tcp in (False, True):
                result = query(tcp=tcp)
                assert result.rcode() == code
                assert not result.answer
        state["mode"] = "zero"
        for qtype, address in (("A", "0.0.0.0"), ("AAAA", "::")):
            result = query(qtype)
            assert result.answer[0][0].address == address
            assert result.answer[0].ttl == 0
        assert not query("TXT").answer
        state["mode"] = "client"
        for _ in range(2):
            assert query(source="127.0.0.2").rcode() == 3
            assert query(source="127.0.0.1").answer[0][0].address == "192.0.2.123"
        assert {p["protocol"] for p in state["requests"]} == {"tcp", "udp"}
        state["mode"] = "error"
        assert query().rcode() == (0 if fail_mode == "open" else 2)
        processes[0].terminate()
        processes[0].wait(timeout=5)
        assert query().rcode() == (0 if fail_mode == "open" else 2)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        for log in logs:
            log.close()
        policy.shutdown()
        policy.server_close()
        stopped.set()
        dns_thread.join(timeout=2)
        authority.close()
