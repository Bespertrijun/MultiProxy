# DNS setup runbook — the two-DNS-role topology

multiProxy splits DNS into **two distinct roles**. Getting this split right is the
single most important deploy step, because collapsing both roles onto the embedded
GeoDNS creates a bootstrap deadlock (if the panel/GeoDNS is down, agents can no
longer resolve the panel to reconnect).

| Role | Example name        | Served by                              | Purpose |
|------|---------------------|----------------------------------------|---------|
| ①    | `emby.example.com`  | the **self-built embedded GeoDNS**     | Geo/ISP line splitting → returns the right front node's A record. End users point Emby here. |
| ②    | `panel.example.com` | a **stable external provider** (Cloudflare/DNSPod) | Where agents reverse-connect (`wss://panel.example.com/agent`) and where the operator opens the web UI. Also drives DNS-01 ACME for ②'s cert. |

> Role ② is intentionally kept OFF the embedded GeoDNS so a panel/GeoDNS outage
> cannot prevent agents from resolving the panel to reconnect. External providers
> cannot do China ISP-line splitting, so role ① stays self-hosted.

---

## Topology constraints (read first)

- **The apex domain stays on Cloudflare.** You delegate **only** the resolution
  subdomain ① to the self-built GeoDNS via an NS record. Everything else (apex,
  panel ②) remains CF-managed.
- **The GeoDNS/panel host MUST be a dedicated non-NAT host** with:
  - a dedicated **public IP**, and
  - a usable **:53 on both UDP and TCP**.
- **NAT relay nodes CANNOT host the GeoDNS** — they typically get only a forwarded
  port range on a shared IP, with no :53 and no dedicated IP. You therefore need at
  least **one separate non-NAT VPS** for the GeoDNS/panel.
- Some cheap providers **rate-limit or block UDP/53** (DNS-amplification policy).
  Verify before purchase; prefer a clean overseas VPS (mainland :53 attracts
  备案/监管 requirements).
- Free any local resolver off the public :53 (e.g. stop/relocate `systemd-resolved`)
  before starting the panel container.

---

## Step 1 — Delegate the resolution subdomain ① to the GeoDNS (in Cloudflare)

In the Cloudflare dashboard for `example.com`, add **two records**, both
**unproxied / grey-cloud** (DNS-only — the subdomain must bypass CF's proxy/CDN so
it returns the real front IPs, which is required and intended):

```
; 1. an A record naming the GeoDNS host as a nameserver, GREY-CLOUD (DNS only):
ns1.example.com.   A     <GeoDNS public IP>

; 2. delegate the resolution subdomain to that nameserver:
emby.example.com.  NS    ns1.example.com.
```

After this, any query for `emby.example.com` (and names under it) is sent by the
recursor to your GeoDNS host. ECS still reaches the GeoDNS unaffected — the user's
recursor adds the EDNS Client Subnet option, independent of the parent being on CF.

> The delegated subdomain exposes the real front-node IPs (no CF proxy). That is by
> design: end users connect their Emby clients directly to those front IPs.

---

## Step 2 — Configure the GeoDNS zone in the panel

Create a DnsZone whose apex matches the delegated name, via the panel UI or API:

```sh
curl -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"apex_domain":"emby.example.com","default_ttl":30}' \
  https://panel.example.com/api/zones
```

Then create the LineGroup(s) that map (region, ISP) → front nodes and add the front
nodes as members. A group with `match_region` and `match_isp` both unset is a
**catch-all** that matches any client; more-specific groups (region and/or ISP set)
win over the catch-all, and `priority` breaks remaining ties. A query resolves to
the healthy A set of the best-matching group; if no node is healthy and there is no
fallback group, the GeoDNS returns **SERVFAIL** (empty-set policy).

**A-record TTL** is the resolution-domain TTL (`PANEL_TTL` / zone `default_ttl`,
default 30s). It governs how fast end-user-perceived failover can be — kept low so
recursors re-query soon after a node is removed.

---

## Step 3 — Keep the panel control domain ② on the external provider

Leave `panel.example.com` as a normal record on Cloudflare/DNSPod pointing at the
panel host's public IP. Agents connect to `wss://panel.example.com/agent`; the web
UI is served on the same host. The external provider's API also drives the DNS-01
ACME challenge for ②'s TLS certificate.

> Panel-side TLS termination (the cert for ②) is a deploy concern handled in front
> of the panel (e.g. a reverse proxy doing ACME), not by the panel binary itself in
> this phase — see the README "Deferred / needs real infra" list.

---

## Step 4 — Verify

From a machine that can reach the GeoDNS host, query role ① **directly** (bypass
caching recursors so you test the authoritative answer):

```sh
# Authoritative query straight to the GeoDNS host:
dig @<GeoDNS public IP> emby.example.com A

# With an EDNS Client Subnet to simulate a specific China line (e.g. a Telecom /48):
dig @<GeoDNS public IP> emby.example.com A +subnet=<telecom-subnet>/24
```

- A **healthy** node in the matching line group → an `A` answer (and the ECS scope
  is echoed when you sent `+subnet`).
- **No healthy node** in the matching group (and no fallback) → `SERVFAIL`.

The authoritative failover SLO is "detect → removed from the :53 answer ≤ 30s" when
queried directly; end-user-perceived failover additionally depends on recursors
honoring the low TTL (best-effort, not a hard guarantee).
