"""Loopback-only asynchronous PowerDNS Recursor -> Blockinator policy bridge."""
import asyncio
import ipaddress
import json
import logging
import math
import os
import signal
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import dns.rdatatype
import httpx

LOG = logging.getLogger("blockinator.powerdns")
MAX_PACKET = 4096
MAX_RESPONSE = 16384


@dataclass(frozen=True)
class Config:
    endpoint: str
    api_key: str = field(repr=False)
    server_id: str = "powerdns-1"
    port: int = 53001
    timeout: float = 0.25
    max_inflight: int = 128

    def __post_init__(self):
        url = urlsplit(self.endpoint)
        if (url.scheme not in {"http", "https"} or not url.hostname
                or url.username is not None or url.password is not None
                or url.fragment or url.query or url.path != "/api/v1/decision"):
            raise ValueError("Endpoint must be an http(s) URL ending in /api/v1/decision")
        if len(self.api_key) < 24 or any(ord(c) < 33 or ord(c) > 126 for c in self.api_key):
            raise ValueError("POLICY_API_KEY must contain at least 24 printable characters")
        if not 1 <= len(self.server_id) <= 255:
            raise ValueError("POWERDNS_SERVER_ID must contain 1 to 255 characters")
        if not 1 <= self.port <= 65535:
            raise ValueError("POWERDNS_BRIDGE_PORT must be between 1 and 65535")
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 1:
            raise ValueError("POWERDNS_TIMEOUT_MS must be greater than 0 and at most 1000")
        if not 1 <= self.max_inflight <= 4096:
            raise ValueError("POWERDNS_MAX_INFLIGHT must be between 1 and 4096")

    @classmethod
    def from_environment(cls):
        return cls(
            endpoint=os.environ["BLOCKINATOR_ENDPOINT"],
            api_key=os.environ["POLICY_API_KEY"],
            server_id=os.getenv("POWERDNS_SERVER_ID", "powerdns-1"),
            port=int(os.getenv("POWERDNS_BRIDGE_PORT", "53001")),
            timeout=float(os.getenv("POWERDNS_TIMEOUT_MS", "250")) / 1000,
            max_inflight=int(os.getenv("POWERDNS_MAX_INFLIGHT", "128")),
        )


def decode_query(packet, server_id):
    if len(packet) > MAX_PACKET:
        raise ValueError("oversized packet")
    version, ip, port, protocol, qtype, name = packet.decode("ascii").split("\n")
    if version != "v1" or protocol not in {"tcp", "udp"}:
        raise ValueError("invalid protocol")
    ip = str(ipaddress.ip_address(ip))
    port, qtype = int(port), int(qtype)
    if not 0 <= port <= 65535 or not 0 <= qtype <= 65535:
        raise ValueError("invalid port or query type")
    name = bytes.fromhex(name).decode("ascii")
    if not 1 <= len(name) <= 254 or any(ord(c) < 33 or ord(c) > 126 for c in name):
        raise ValueError("invalid DNS name")
    return {"server_id": server_id, "protocol": protocol,
            "client": {"ip": ip, "port": port},
            "dns": {"questions": [{"name": name,
                    "type": dns.rdatatype.to_text(qtype), "class": "IN"}]}}


def decode_decision(body):
    decision = json.loads(body)
    if not isinstance(decision, dict) or type(decision.get("block")) is not bool:
        raise ValueError("invalid block decision")
    if not decision["block"]:
        return b"allow"
    mode = decision.get("response_mode")
    if not isinstance(mode, str) or mode not in {"nxdomain", "refused", "nodata", "zero"}:
        raise ValueError("invalid response mode")
    return mode.encode("ascii")


class Bridge(asyncio.DatagramProtocol):
    def __init__(self, config, client):
        self.config = config
        self.client = client
        self.transport = None
        self.tasks = set()
        self.failed = 0
        self.overloaded = 0
        self.invalid = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, packet, address):
        if not ipaddress.ip_address(address[0]).is_loopback:
            return
        try:
            payload = decode_query(packet, self.config.server_id)
        except (ValueError, UnicodeError):
            self.invalid += 1
            self.transport.sendto(b"error", address)
            return
        if len(self.tasks) >= self.config.max_inflight:
            self.overloaded += 1
            self.transport.sendto(b"error", address)
            return
        task = asyncio.create_task(self.respond(payload, address))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def decision(self, payload):
        # Bound both body size and total wall-clock time (including pool wait).
        async with self.client.stream("POST", self.config.endpoint, json=payload,
                                      headers={"X-API-Key": self.config.api_key}) as response:
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=MAX_RESPONSE + 1):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE:
                    raise ValueError("oversized policy response")
            return decode_decision(body)

    async def respond(self, payload, address):
        try:
            action = await asyncio.wait_for(self.decision(payload), self.config.timeout)
        except (httpx.HTTPError, ValueError, TimeoutError):
            self.failed += 1
            action = b"error"
        if self.transport is not None and not self.transport.is_closing():
            self.transport.sendto(action, address)

    async def close(self):
        if self.transport is not None:
            self.transport.close()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


async def serve(config):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    # No redirects or ambient proxy settings: never forward the key to another host.
    async with httpx.AsyncClient(
        timeout=config.timeout, follow_redirects=False, trust_env=False,
        limits=httpx.Limits(max_connections=config.max_inflight,
                           max_keepalive_connections=min(32, config.max_inflight)),
    ) as client:
        bridge = Bridge(config, client)
        await loop.create_datagram_endpoint(lambda: bridge, local_addr=("127.0.0.1", config.port))
        LOG.info("Listening on 127.0.0.1:%s", config.port)
        try:
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), 60)
                except TimeoutError:
                    pass
                if bridge.failed or bridge.overloaded or bridge.invalid:
                    LOG.warning("Policy failures=%d overloads=%d invalid packets=%d (cumulative)",
                                bridge.failed, bridge.overloaded, bridge.invalid)
        finally:
            await bridge.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        config = Config.from_environment()
    except (KeyError, ValueError):
        raise SystemExit("Invalid bridge environment; check the PowerDNS setup guide") from None
    asyncio.run(serve(config))
