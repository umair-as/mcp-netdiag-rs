# MCP NetDiag Architecture Flow

This is the troubleshooting flow for `mcp-netdiag-rs`, modeled after your reference sequence.

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant APP as Our App / Orchestrator
    participant MC as MCP Client
    participant MS as mcp-netdiag-rs (MCP Server)
    participant OS as Embedded Linux CLI

    U->>APP: "Why can't host 10.10.20.55 reach gateway?"
    APP->>MC: Need available diagnostics tools
    MC->>MS: tools/list
    MS-->>MC: tools metadata (net.if_status, net.neighbors, ...)
    MC-->>APP: Tool catalog for planning

    APP->>MC: Query + selected tools context

    Note over APP,MC: Example execution plan chosen by LLM/orchestrator

    APP->>MC: Run net.if_status(interface="swp3")
    MC->>MS: tools/call(name="net.if_status", args)
    MS->>OS: ip -j -s link show dev swp3
    OS-->>MS: JSON counters/state
    MS-->>MC: toolResult(content=json)
    MC-->>APP: Interface diagnostics

    APP->>MC: Run net.neighbors(interface="vlan20")
    MC->>MS: tools/call(name="net.neighbors", args)
    MS->>OS: ip -j neigh show dev vlan20
    OS-->>MS: Neighbor table
    MS-->>MC: toolResult
    MC-->>APP: Neighbor diagnostics

    APP->>MC: Run net.routes()
    MC->>MS: tools/call(name="net.routes", args={})
    MS->>OS: ip -j route show table all
    OS-->>MS: Routing table
    MS-->>MC: toolResult
    MC-->>APP: Route diagnostics

    APP->>MC: Optional net.ping(target="10.10.20.1", count=3)
    MC->>MS: tools/call(name="net.ping", args)
    MS->>OS: ping -n -c 3 -W 2 10.10.20.1
    OS-->>MS: Ping output
    MS-->>MC: toolResult
    MC-->>APP: Connectivity evidence

    APP-->>U: Diagnosis + actions
    Note over APP,U: "Link up, no RX errors; ARP incomplete on vlan20;\nmissing route to 10.10.20.0/24 likely cause."
```

## Tool-to-Command Mapping

- `net.if_status` -> `ip -j -s link show [dev <interface>]`
- `net.mac_lookup` -> `bridge -j fdb show to <mac>`
- `net.neighbors` -> `ip -j neigh show [dev <interface>]`
- `net.routes` -> `ip -j route show table all`
- `net.ping` -> `ping -n -c <1..10> -W <1..5> <target>`
- `net.traceroute` -> `traceroute -n -m <1..30> <target>`
- `net.logs` -> `journalctl --no-pager --output=short-iso -n <1..200> [-u <unit>]`

## Guardrails in Current Implementation

- Read-only diagnostics only (no config mutation commands).
- Allowlisted commands only.
- Bounded execution time (`timeout`).
- Bounded output size/line count.
- Input validation for interface/target/mac fields.
