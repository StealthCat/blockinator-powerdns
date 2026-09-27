# Blockinator PowerDNS

Use Blockinator's existing client scopes, lists, schedules, whitelist rules and query
logging from **PowerDNS Recursor**. This is a Recursor Lua DNS hook plus a local
Python bridge; it is not a PowerDNS Authoritative backend or a dnsdist plugin.
The Blockinator server API does not need any changes.

Each client query reaching `preresolve` is sent asynchronously over loopback UDP to
the bridge, which calls `/api/v1/decision` with `X-API-Key`. Allowed queries continue
normal recursion. Blocked queries receive the configured Blockinator response:

| Response mode | DNS response |
| --- | --- |
| `nxdomain` | NXDOMAIN |
| `refused` | REFUSED |
| `nodata` | NOERROR with no answers |
| `zero` | `0.0.0.0` for A, `::` for AAAA, no answers for other types |

## Install on the Recursor host

These instructions target Linux with systemd, Python 3.10+ and an existing
PowerDNS Recursor installation. CI exercises Ubuntu 24.04's packaged Recursor.
Install Blockinator first using the [primary Docker Compose instructions](https://github.com/StealthCat/blockinator-web#readme).
Run the bridge in the **same network namespace** as Recursor: both use
`127.0.0.1:53001`. These instructions assume a host-installed Recursor.

Clone this plugin repository, then install the bridge:

```bash
git clone https://github.com/StealthCat/blockinator-powerdns.git
cd blockinator-powerdns
sudo apt-get install python3-venv
sudo install -d -m 755 /opt/blockinator-powerdns
sudo install -m 644 bridge.py /opt/blockinator-powerdns/
sudo install -m 644 requirements.txt /opt/blockinator-powerdns/
sudo python3 -m venv /opt/blockinator-powerdns/venv
sudo /opt/blockinator-powerdns/venv/bin/pip install -r /opt/blockinator-powerdns/requirements.txt
sudo install -m 600 bridge.env.example /etc/blockinator-powerdns.env
sudoedit /etc/blockinator-powerdns.env
```

Set `POLICY_API_KEY` to the policy key already configured in Blockinator (not the
administrator password). Set `BLOCKINATOR_ENDPOINT` to the reachable policy URL:

```ini
BLOCKINATOR_ENDPOINT=http://127.0.0.1:8080/api/v1/decision
POLICY_API_KEY=your-existing-policy-api-key
POWERDNS_SERVER_ID=powerdns-1
POWERDNS_TIMEOUT_MS=250
POWERDNS_MAX_INFLIGHT=128
POWERDNS_BRIDGE_PORT=53001
```

The example endpoint works when Blockinator's Compose stack is on this host and
Caddy is serving HTTP on port 8080. For another host, use your HTTPS endpoint and
a certificate trusted by the bridge host. TLS verification is enabled; redirects
are deliberately rejected. If Caddy redirects HTTP to HTTPS, configure the final
HTTPS URL directly. Do not point this URL at a resolver whose DNS lookups depend on
this bridge: use a locally resolvable hostname or a static `/etc/hosts` entry to
avoid a policy-lookup loop.

```bash
sudo install -m 644 blockinator-powerdns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now blockinator-powerdns
sudo systemctl status blockinator-powerdns
sudo install -m 644 blockinator.lua /etc/powerdns/blockinator.lua
```

If needed, edit `bridge` and `failMode` at the top of
`/etc/powerdns/blockinator.lua`. The Lua port and `POWERDNS_BRIDGE_PORT` must match.
Choose how DNS behaves when Blockinator is unavailable:

- `open` (default): continue normal resolution.
- `closed`: return SERVFAIL. This also applies to invalid API replies and overload.

Enable the DNS hook in your Recursor configuration. For **YAML configuration**,
add the following to the existing `recursor` section (do not create duplicate keys):

```yaml
recursor:
  lua_dns_script: /etc/powerdns/blockinator.lua
```

For **legacy `recursor.conf` configuration**, use:

```ini
lua-dns-script=/etc/powerdns/blockinator.lua
```

Use the format your Recursor installation already uses. This is the DNS hook
setting, **not** `lua-config-file` / `recursor.lua_config_file`. If you already
have a Lua DNS script, merge its `preresolve` logic and the callback deliberately;
loading this script replaces the existing hook. Restart Recursor when enabling
or removing this integration so old packet-cache entries cannot bypass policy:

```bash
sudo systemctl restart pdns-recursor
```

Keep Recursor's `allow-from` / `incoming.allow_from` restricted to your intended
clients. The bridge binds only to IPv4 loopback and should never be port-forwarded
or exposed to a LAN. The loopback protocol assumes the resolver host is trusted.
For a containerized Recursor, run the bridge in the same container network
namespace and mount the Lua hook there; separate default Docker networks do not
share localhost. The systemd example does not set up that container topology.

## Verify

Create a blacklist entry in Blockinator for `blocked.example`, assign it to a
scope matching the testing client's address, and query your Recursor:

```bash
dig @RECURSOR-IP blocked.example A
dig @RECURSOR-IP blocked.example AAAA
dig +tcp @RECURSOR-IP blocked.example A
dig @RECURSOR-IP example.com A
sudo journalctl -u blockinator-powerdns --since '5 minutes ago'
```

Check Blockinator's query history for the client IP, question type, UDP/TCP
protocol and `powerdns-1` server ID. Test from a second client outside the blocking
scope too. The plugin uses the requesting client's address, not an EDNS Client
Subnet supplied by the client. NAT or a DNS proxy can therefore collapse multiple
clients into one scope unless Recursor is configured separately to restore their
trusted source identity.

## Reliability and performance

The hook uses PowerDNS's asynchronous `udpQueryResponse` follow-up, so the HTTP
call does not block a Recursor worker. The bridge reuses HTTP connections, permits
128 concurrent requests by default, has no waiting queue, limits response size,
and enforces a total 250 ms HTTP deadline. Excess requests immediately take the
selected failure path. The timeout is configurable up to 1000 ms. If the bridge
itself is stopped, Recursor's own UDP follow-up timeout applies instead; it is not
controlled by `POWERDNS_TIMEOUT_MS`.

The Lua hook disables insertion into Recursor's packet cache for both allowed and
blocked queries. This prevents a cached decision from crossing client scopes or
outliving a policy change. Recursor's underlying DNS record cache still works.
There is no additional policy-decision cache in the bridge. Expect one HTTP policy
request per query reaching the hook; size Blockinator and the concurrency limit
for your DNS load. Responses generated earlier by Recursor (for example built-in
CHAOS queries, ACL rejection, or an earlier RPZ policy) do not reach `preresolve`.
Existing RPZ rules still apply independently; a Blockinator whitelist cannot
reverse an earlier Recursor policy action.

Synthetic address answers have TTL 0. NXDOMAIN/NODATA replies have no synthetic
SOA. Clients may still retain earlier responses according to their own caching
behavior. This integration evaluates the original client question, not every
CNAME target contacted during recursion. Query wire bytes and EDNS metadata are
not sent to Blockinator.

The bridge logs cumulative error/overload counts at most once per minute without
logging API keys or individual queries. API failures include non-2xx responses,
redirects, malformed decisions, TLS failures and timeouts. In fail-open mode,
those queries can resolve without a Blockinator query-log entry.

## Update or remove

To update, copy the new bridge and Lua files, install the listed dependencies,
and restart both services. Back up your local Lua settings before replacing the
file. To remove, delete the Lua DNS hook setting (or restore your previous
script), restart Recursor, then disable the bridge:

```bash
sudo systemctl disable --now blockinator-powerdns
```

## Tests and upstream references

```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q tests/test_powerdns.py
```

With `pdns_recursor` installed, the suite also starts a real isolated resolver, a
local DNS upstream and a mock policy API. It checks all response modes, UDP/TCP,
per-client cache isolation, API failure and stopped-bridge behavior in both failure
modes. Without the binary, only those two live tests are skipped.

- [PowerDNS Lua hooks and asynchronous follow-up actions](https://docs.powerdns.com/recursor/lua-scripting/hooks.html)
- [DNSQuestion fields](https://docs.powerdns.com/recursor/lua-scripting/dq.html)
- [PowerDNS YAML settings](https://docs.powerdns.com/recursor/yamlsettings.html)

## License

Licensed under [GNU GPL v3.0](LICENSE).
