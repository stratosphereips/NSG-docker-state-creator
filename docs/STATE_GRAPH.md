# State graph

The state graph is a deterministic, evidence-backed view of what the agent in
the observed container could know. It is designed for rule-based agents now and
graph or text embeddings later. It does not claim that every observed packet or
file is consciously understood by a human; `knowledge_source`, evidence, and
confidence preserve why each fact entered the model.

## Outputs

The live compiler writes three files atomically under `/observation/state`:

| File | Purpose |
|---|---|
| `graph.json` | Complete directed property graph, provenance, and embedded core summary |
| `summary.json` | Only the six required state categories plus counts |
| `embedding.jsonl` | One canonical text document per node and edge |

`embedding.jsonl` is intentionally model-neutral. Its records have `id`,
`kind`, `type`, `text`, and metadata. Generate vectors from `text`, retain `id`
as the lookup key, and use the source/target IDs on edge documents to reconstruct
topology after nearest-neighbor retrieval.

## Detail levels

- `forensic` retains individual processes, network-flow edges, all non-excluded
  accessed or changed data, and up to 1,000 complete source records per entity.
- `operational` aggregates executions by program, retains flows, uses the
  configurable general file filter, and stores up to 50 source/line references
  per entity.
- `strategic` drops process and flow detail, retains only important files, and
  keeps evidence counts and source names. Core topology and conclusions remain.

All levels contain `known_networks`, `known_hosts`, `controlled_hosts`,
`known_data`, `known_services`, and `known_blocks` in `summary`.

## Core entities and relationships

The fixed `agent:observed` node represents whichever human or program is acting
inside the container. `host:local` is the monitored environment and is always
controlled. Remote hosts use normalized IP or DNS-name identities.

Important relationships include:

```text
agent:observed --RUNS_ON---------> host:local
agent:observed --KNOWS_HOST------> host
agent:observed --CONTROLS--------> host
agent:observed --KNOWS_NETWORK---> network
agent:observed --KNOWS_SERVICE---> service
agent:observed --KNOWS_DATA------> data
agent:observed --KNOWS_BLOCK-----> block
host           --HOSTS_SERVICE---> service
host           --STORES_DATA-----> data
host           --MEMBER_OF-------> network
block          --MAY_BLOCK-------> host, service, or network
```

Nodes and edges carry `confidence`, `evidence_count`, `evidence_sources`, and
level-dependent evidence. Stable IDs are derived from semantic identity rather
than observation order, so the same entity can be compared across rebuilds.

## Inference rules

Known networks come from configured interface prefixes and routes. An observed
IP that is outside those sources also creates a `/32` or `/128` host route so
the model never invents a broader subnet. Known hosts come from interfaces,
gateways, neighbors, sockets, Zeek flows/DNS, command targets, and assertions.

Services come from local listeners, target or responder ports, Zeek protocol
identification, HTTP, DNS, SSH, and assertions. A targeted port is labeled
`targeted` or `attempted`; response evidence promotes it to `observed` or
`open`. Common ports receive a configured name when protocol identification is
not available.

Data comes from file changes, reconciliation, successful or attempted workload
file syscalls, command arguments, HTTP resources, Zeek file analysis, successful
SCP/SFTP commands, and assertions. It is always indexed by host through a
`STORES_DATA` edge and the `known_data` map.

Remote control is intentionally conservative:

- the local container is controlled by definition;
- Zeek SSH `auth_success=true` is 0.99 confidence;
- an interactive Bash audit record showing `ssh`, `scp`, or `sftp` exit status
  zero is 0.95 confidence;
- an explicit assertion uses the supplied confidence.

A TCP handshake alone only means that a host/service is known. An exploit over
an encrypted or custom protocol cannot be proven from local network metadata;
use an assertion or add a protocol-specific extractor when the agent reports
success.

Known blocks are explicitly hypotheses unless backed by declared local policy.
Current evidence includes:

- iptables/nftables DROP or REJECT rules: 0.99 confidence;
- syscall `EACCES`: 0.90;
- connect timeout: 0.82;
- a Zeek no-reply state such as `S0`: 0.78;
- host/network unreachable: 0.50-0.55;
- rejected or reset connections: 0.55.

The compiler does not treat `ECONNREFUSED` as a firewall block by default: it
usually proves the host replied and the port was closed. Duplicate evidence is
aggregated on one block node per target and reason.

## File filters and custom configuration

Defaults are in `observer/etc/state-graph.json`. Supply a JSON override with
`--config`; nested objects are merged over the defaults. Regular expressions
under `data.include_regex` select operational files, `important_regex` selects
strategic files, and `exclude_regex` applies to every level.

Example override:

```json
{
  "data": {
    "include_regex": ["^/workspace/", "\\.(pcap|parquet)$"],
    "important_regex": ["^/workspace/targets\\.json$"]
  },
  "block_inference": {
    "minimum_confidence": 0.7
  }
}
```

Run it against retained observations:

```bash
state-builder \
  --input /observation \
  --output /observation/custom-state \
  --level strategic \
  --config /path/to/override.json
```

## Assertions for facts passive observation cannot prove

Write optional JSON Lines records to `/observation/state-assertions.jsonl`.
This is useful when an exploit framework or agent has authoritative success
knowledge that encrypted traffic cannot reveal.

```json
{"type":"controlled_host","host":"10.0.0.25","mechanism":"exploit-success","confidence":1.0,"note":"session 7 opened"}
{"type":"known_file","host":"10.0.0.25","path":"/etc/shadow","confidence":0.95}
{"type":"known_service","host":"10.0.0.25","protocol":"tcp","port":5432,"service":"postgresql","status":"open","confidence":0.99}
```

Assertions are evidence, not magic overrides: they remain visible as
`operator-assertion` provenance and participate in the same confidence model.

## One-shot use outside the observed container

The compiler has no non-standard Python dependency. From this repository:

```bash
observer/bin/state-builder \
  --input observation/demo-run \
  --output observation/demo-run/state \
  --level operational
```

Use `jq '.summary' observation/demo-run/state/graph.json` for a readable view.
PCAP is not parsed directly because Zeek already supplies the structured flow
and application evidence; the PCAP remains available for future extractors.
