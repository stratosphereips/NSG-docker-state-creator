"""Agent-scoped measurement (maintainer directive 2026-11-11).

Directive (verbatim): "FMs should be given to each AGENT, not to the hosts."
The per-host CLI (``analysis.analyze <obs-host-dir>``) keys every FM unit on
the HOST's workload tree — one FM<id>/run per host — which charges estate
behavior on estate hosts and has no concept of multiple measured agents.  The
program measures AGENTS: a pentester agent (attacker FMs plus the shared
surfaces), a defender agent (defender FMs plus the shared surfaces), with the
FM -> role mapping fixed by the ``role`` field of
``fm_measurement/registry/fm_registry.json``.  The l1 lesson
(fm_measurement/docs/FM_STORY_20261111.md): the actor tree exists on ONE host
while the evidence spans many (the wire capture lives on the router host).

MODE (HARD REQUIREMENT, 2026-11-11 — supersedes the opt-in design):
``python3.12 -m analysis.analyze <obs> [--config DIR]`` measures PER AGENT
BY DEFAULT, where ``<obs>`` is a MULTI-HOST observation directory (per-host
stream dirs as immediate subdirectories — the l1 mirror-tree layout,
``<obs>/<host>/``) or a single-host stream dir.  Agent trees are DISCOVERED
automatically on every host: the supervisor workload bracket delimits each
host's monitored tree and the opencode-serve census pattern
(``AGENT_CENSUS_PATTERNS``) picks the agent identities inside it (the NSG
agent fleet — the coder56 attacker, the soc_god defender — all run as
``opencode serve`` sessions).  Every FM unit is keyed ``FM<id>/agent=<id>``
(run-level units; per-unit detectors keep their unit shape inside the key:
``FM4.2/agent=<id>/victim=60@90``), one verdict set per agent plus an
aggregate summary block.

ROLES stay human-declared, identities auto-resolve: ``DIR/agents.json``
carries EITHER the minimal run-level role map::

    {"contract_version": "2026-11-agents-1",
     "roles": {"<host-dir-name>": "attacker" | "defender"}}

(the form the campaign runner emits automatically per run) OR the full
per-agent form below — both accepted, both may be combined.  NO role map
-> every discovered agent's role is ``unknown``: only shared-surface FMs
(SFM2/SFM4/SFM5) decide while every role-scoped FM emits a run-level
UNMEASURED carrying ``agents:role_undeclared`` — fail-closed, never
guessed (A8'); roles for unknown hosts are NOT inferred from names.

Estate hosts with no agent census match contribute EVIDENCE ONLY (wire
joins, cross-host zeek) and get NO FM units — structurally eliminating the
l1 artifact class (samba unshare / sshd reaping charged to estate
"workloads").  A census match OUTSIDE the supervisor workload bracket is
named (``agents:agent_unbracketed``) and never measured.  An observation
with no agent trees at all yields ZERO FM units + summary flag
``agents:none_detected`` — honest empty, never a per-host fallback.

CLI: ``--agent <id>`` restricts the battery to one agent (registry-declared
or discovered); ``--per-host`` is the explicitly-requested LEGACY/debug
mode reproducing the pre-2026-11-11 per-host CLI byte-for-byte — without
it, per-host output never appears.

FULL-FORM AGENT REGISTRY (``DIR/agents.json``, host-drawn config outside
the agent's reach — the fm_4.2 victim-manifest / attacker_opencode_roots
precedent)::

    {
      "contract_version": "2026-11-agents-1",
      "agents": [
        {
          "id": "pentester",
          "role": "attacker",                    # attacker | defender
          "surfaces": ["attacker", "shared"],    # optional; default
                                                 # [role, "shared"]
          "workload_roots": {
            "client-attacker": {                 # host dir name in <obs>
              "census_identities": [             # exact census keys (raw
                {"pid": 124, "start_ticks": "110076"}   # string start_ticks)
              ],
              "cmdline_patterns": ["^opencode( |$)"]    # census cmdline
            }
          }
        }
      ]
    }

Absent or invalid -> ALL agent-attributed measurement fails closed (every
FM unit UNMEASURED carrying a named ``agents:`` flag) — never guessed, per
the house fail-closed discipline (G-21).  One home host per agent (the l1
model: the actor tree exists on one host); a multi-home declaration is a
named fail-closed flag, never a guess about which bracket wins.

EVIDENCE RESOLUTION ACROSS HOSTS.  The home host supplies every attribution
plane (supervisor bracket, census, strace, files, tty, bcc, health, ss
inventory — the planes whose records join by (pid, start_ticks) identity,
which would collide across hosts).  The WIRE plane spans hosts: the zeek
conn.log directories of ALL hosts in the observation are consulted (the
router's capture sees the agent's flows; zeek records are IP-keyed, so no
pid collision exists), and a peer host's ``sensor_started name=zeek``
declaration arms the zeek-reading detector halves exactly like a home
declaration.  The rotating tcpdump pcap is declared residual: no analysis
detector parses pcap bytes (the l1 story read them with an external
parser).

Multi-plane honesty is inherited, not reimplemented: a home host with no
trace plane but live census/sockets/wire planes still decides what those
planes support (AFM3's zeek ceiling breaches FAIL over the trace-hole
flags) while every trace-anchored half emits its named
``<FM>:trace_file_missing``-family degradation — the per-host l1 finding,
now made explicit at agent level.

Back-compat: ``--per-host`` reproduces the per-host behavior byte-identical
to the pre-2026-11-11 CLI; the library entry ``analysis.analyze.run_analysis``
keeps ``per_host=True`` as its default so detector-level callers are
unaffected, while the CLI default is per-agent auto.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import streamkit
from .integrity import StreamFlag
from .observation import DEFAULT_ENVELOPE_PINS, EnvelopePins, Observation, \
    load_observation
from .verdict import UnitResult

#: Registry file name inside the --config DIR (host-drawn, like fm_4_2.json).
AGENTS_REGISTRY_FILENAME = "agents.json"

#: The canonical FM -> role registry, also overridable from the config DIR
#: (DIR/fm_registry.json first, then the repo copy).
ROLE_REGISTRY_FILENAME = "fm_registry.json"
REPO_ROLE_REGISTRY = (
    Path(__file__).resolve().parent.parent / "fm_measurement" / "registry"
    / ROLE_REGISTRY_FILENAME)

#: Valid agent roles and FM families (the registry's role vocabulary).
AGENT_ROLES = ("attacker", "defender")
FM_FAMILIES = ("attacker", "defender", "shared")

#: Role value carried by every agent whose home host has no declared role.
#: Not a valid DECLARED role (AGENT_ROLES): it can only arise from absence,
#: never from a human writing "unknown" into the map.
ROLE_UNKNOWN = "unknown"

#: The auto-discovery census patterns (the "opencode-serve census"): the
#: NSG agent fleet runs as ``opencode serve`` sessions (the coder56
#: attacker, the soc_god defender), so a census cmdline starting with the
#: opencode binary inside a supervisor workload bracket IS an agent tree.
#: Estate processes (smbd, sshd, nc, tail) never match — the structural
#: fix for the l1 artifact class.
AGENT_CENSUS_PATTERNS = (re.compile(r"^opencode( |$)"),)

#: Marker paths qualifying a subdirectory of <obs> as one host's stream dir
#: (any one suffices; the l1 mirror-tree layout carries several per host).
_HOST_DIR_MARKERS = (
    "supervisor.jsonl",
    "processes.jsonl",
    "health.json",
    "sockets/sockets.jsonl",
    "files/events.jsonl",
    "files/reconciliation.jsonl",
    "bcc/status.jsonl",
    "syscalls",
    "tty",
    "zeek",
)


# ---------------------------------------------------------------------------
# Agent registry (fail-closed loader)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RootSpec:
    """One agent's attribution roots on one host (validated, pure data)."""

    census_identities: tuple[tuple[int, str], ...] = ()
    cmdline_patterns: tuple[re.Pattern, ...] = ()

    def is_empty(self) -> bool:
        return not self.census_identities and not self.cmdline_patterns


@dataclass(frozen=True)
class AgentSpec:
    """One measured agent: role, FM families, and per-host roots."""

    id: str
    role: str
    surfaces: tuple[str, ...]
    roots_by_host: Mapping[str, RootSpec] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentsRegistry:
    """Parsed agents.json.  ``flags`` non-empty means the FILE failed
    closed (no usable registry); per-agent validation failures omit that
    agent from ``agents`` and carry its flags in ``invalid``.

    Two file forms are accepted (and may be combined):

    - full form: ``{"contract_version", "agents": [...]}`` — declared
      agents with workload roots (``agents`` populated);
    - minimal roles form: ``{"roles": {"<host>": role}}`` — the run-level
      role map the campaign runner emits (``roles_by_host`` populated).
      In auto-discovery mode the map is the only human input: identities
      resolve from the census, roles come from the home host.
    """

    agents: Mapping[str, AgentSpec] = field(default_factory=dict)
    invalid: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    flags: tuple[str, ...] = ()
    #: Minimal roles form: host dir name -> "attacker" | "defender".
    #: Hosts absent from the map are ``unknown`` (never name-inferred).
    roles_by_host: Mapping[str, str] = field(default_factory=dict)

    def flags_for(self, agent_id: str) -> tuple[str, ...]:
        """Every registry-level flag relevant to ``agent_id`` (file-level
        flags plus the agent's own validation flags, if any)."""
        return self.flags + self.invalid.get(agent_id, ())


def _invalid_agent(flags: list[str], agent_id: str, detail: str) -> None:
    who = agent_id if agent_id else "<unnamed>"
    flags.append(f"agents:agent_invalid id={who} {detail}")


def _parse_roots(raw, agent_id: str, flags: list[str]) -> Mapping[
        str, RootSpec]:
    """Validate one agent's workload_roots mapping (host -> RootSpec)."""
    if not isinstance(raw, Mapping) or not raw:
        _invalid_agent(flags, agent_id, "workload_roots_absent")
        return {}
    roots: dict[str, RootSpec] = {}
    for host, entry in raw.items():
        if not isinstance(host, str) or not host.strip():
            _invalid_agent(flags, agent_id, "host_name_invalid")
            continue
        if not isinstance(entry, Mapping):
            _invalid_agent(flags, agent_id, f"roots_entry_invalid host={host}")
            continue
        identities: list[tuple[int, str]] = []
        raw_ids = entry.get("census_identities")
        if raw_ids is not None:
            if not isinstance(raw_ids, (list, tuple)):
                _invalid_agent(flags, agent_id,
                               f"census_identities_not_list host={host}")
            else:
                for item in raw_ids:
                    if not isinstance(item, Mapping):
                        _invalid_agent(flags, agent_id,
                                       f"root_identity_invalid host={host}"
                                       f" entry={item!r}")
                        continue
                    pid = item.get("pid")
                    ticks = item.get("start_ticks")
                    if (isinstance(pid, bool) or not isinstance(pid, int)
                            or not isinstance(ticks, str) or not ticks):
                        _invalid_agent(flags, agent_id,
                                       f"root_identity_invalid host={host}"
                                       f" entry={item!r}")
                        continue
                    identities.append((pid, ticks))
        patterns: list[re.Pattern] = []
        raw_patterns = entry.get("cmdline_patterns")
        if raw_patterns is not None:
            if not isinstance(raw_patterns, (list, tuple)):
                _invalid_agent(flags, agent_id,
                               f"cmdline_patterns_not_list host={host}")
            else:
                for pattern in raw_patterns:
                    if isinstance(pattern, str):
                        try:
                            patterns.append(re.compile(pattern))
                            continue
                        except re.error:
                            pass
                    _invalid_agent(flags, agent_id,
                                   f"root_pattern_invalid host={host}"
                                   f" pattern={pattern!r}")
        spec = RootSpec(census_identities=tuple(identities),
                        cmdline_patterns=tuple(patterns))
        if spec.is_empty():
            _invalid_agent(flags, agent_id, f"roots_empty host={host}")
            continue
        roots[host] = spec
    return roots


def _parse_roles_map(
    raw, path: Path,
) -> tuple[dict[str, str], list[str]]:
    """Validate the minimal roles form (``{"roles": {host: role}}``).

    Invalid entries are named (``agents:role_invalid``) and omitted — the
    host then resolves to role ``unknown`` in auto-discovery, never to a
    name-guessed role.  Absence of the key is not an error here (the full
    form has no roles key); an empty/non-object ``roles`` value is named.
    """
    if raw is None:
        return {}, []
    flags: list[str] = []
    if not isinstance(raw, Mapping):
        return {}, [f"agents:registry_invalid path={path} roles_not_object"]
    if not raw:
        return {}, [f"agents:registry_invalid path={path} roles_empty"]
    roles: dict[str, str] = {}
    for host, role in raw.items():
        if not isinstance(host, str) or not host.strip():
            flags.append(f"agents:role_invalid host={host!r} role={role!r}"
                         " host_name_invalid")
            continue
        if role not in AGENT_ROLES:
            flags.append(f"agents:role_invalid host={host} role={role!r}")
            continue
        roles[host] = role
    return roles, flags


def load_agents_registry(config_dir: Path | None) -> AgentsRegistry:
    """Load ``DIR/agents.json``; total, fail-closed, never guesses.

    Accepts BOTH forms: the full per-agent form (``contract_version`` +
    ``agents`` with declared workload roots) and the minimal run-level
    roles form (``roles: {host: role}`` — the campaign runner's emission);
    a file carrying both is parsed as both.  A missing file yields
    ``agents:registry_missing``; a malformed one
    ``agents:registry_invalid ...``; invalid agent entries are named and
    excluded (requesting one later fails closed through
    :meth:`AgentsRegistry.flags_for`).
    """
    if config_dir is None:
        return AgentsRegistry(flags=(
            "agents:registry_missing config_dir_absent",))
    path = Path(config_dir) / AGENTS_REGISTRY_FILENAME
    if not path.is_file():
        return AgentsRegistry(flags=(f"agents:registry_missing path={path}",))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return AgentsRegistry(flags=(
            f"agents:registry_invalid path={path} error={error}",))
    if not isinstance(data, Mapping):
        return AgentsRegistry(flags=(
            f"agents:registry_invalid path={path} not_object",))

    roles_by_host, role_flags = _parse_roles_map(data.get("roles"), path)

    flags: list[str] = list(role_flags)
    raw_agents = data.get("agents")
    has_agents = isinstance(raw_agents, (list, tuple)) and bool(raw_agents)
    if "agents" in data and not has_agents and roles_by_host:
        # A roles-form file with a garbage agents key: name it, keep roles.
        flags.append(f"agents:registry_invalid path={path} agents_ignored")
    if not has_agents and not roles_by_host:
        version = data.get("contract_version")
        if not isinstance(version, str) or not version.strip():
            flags.append(f"agents:registry_invalid path={path}"
                         f" contract_version={version!r}")
        flags.append(f"agents:registry_invalid path={path} agents_absent")
        return AgentsRegistry(flags=tuple(flags))
    if not has_agents:
        return AgentsRegistry(flags=tuple(flags),
                              roles_by_host=dict(roles_by_host))

    version = data.get("contract_version")
    if not isinstance(version, str) or not version.strip():
        flags.append(f"agents:registry_invalid path={path}"
                     f" contract_version={version!r}")

    agents: dict[str, AgentSpec] = {}
    invalid: dict[str, tuple[str, ...]] = {}
    for entry in raw_agents:
        if not isinstance(entry, Mapping):
            flags.append(f"agents:agent_invalid entry={entry!r}")
            continue
        agent_flags: list[str] = []
        agent_id = entry.get("id")
        if not isinstance(agent_id, str) or not agent_id.strip():
            _invalid_agent(agent_flags, "", "id_absent")
            agent_id = ""
        if agent_id and (agent_id in agents or agent_id in invalid):
            flags.append(f"agents:registry_invalid path={path}"
                         f" duplicate_id={agent_id}")
            continue
        role = entry.get("role")
        if role not in AGENT_ROLES:
            _invalid_agent(agent_flags, agent_id, f"role={role!r}")
        surfaces_raw = entry.get("surfaces")
        if surfaces_raw is None:
            surfaces = (role, "shared") if role in AGENT_ROLES else ()
        elif isinstance(surfaces_raw, (list, tuple)) and surfaces_raw \
                and all(s in FM_FAMILIES for s in surfaces_raw):
            surfaces = tuple(dict.fromkeys(surfaces_raw))
        else:
            _invalid_agent(agent_flags, agent_id,
                           f"surfaces={surfaces_raw!r}")
            surfaces = ()
        roots = _parse_roots(entry.get("workload_roots"), agent_id,
                             agent_flags)
        if agent_flags:
            if agent_id:
                invalid[agent_id] = tuple(agent_flags)
            else:
                flags.extend(agent_flags)
            continue
        agents[agent_id] = AgentSpec(
            id=agent_id, role=role, surfaces=surfaces, roots_by_host=roots)
    # Full-form declared agents lend their role to their home hosts for
    # auto-discovery (an explicit roles key already present for a host
    # wins — never overwritten).
    for spec in agents.values():
        if spec.role in AGENT_ROLES:
            for host in spec.roots_by_host:
                roles_by_host.setdefault(host, spec.role)
    return AgentsRegistry(agents=agents, invalid=invalid, flags=tuple(flags),
                          roles_by_host=dict(roles_by_host))


def load_role_registry(
    config_dir: Path | None,
) -> tuple[Mapping[str, str] | None, tuple[str, ...]]:
    """FM id -> role (attacker|defender|shared) from fm_registry.json.

    Lookup: ``DIR/fm_registry.json`` first (a self-contained manifest dir),
    then the repo registry.  ``(None, flags)`` when neither exists or the
    copy is unusable — agent scoping then fails closed (roles unknowable).
    """
    candidates: list[Path] = []
    if config_dir is not None:
        candidates.append(Path(config_dir) / ROLE_REGISTRY_FILENAME)
    candidates.append(REPO_ROLE_REGISTRY)
    for path in candidates:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            return None, (f"agents:role_registry_invalid path={path}"
                          f" error={error}",)
        modes = data.get("modes") if isinstance(data, Mapping) else None
        if not isinstance(modes, (list, tuple)):
            return None, (f"agents:role_registry_invalid path={path}"
                          " modes_absent",)
        roles: dict[str, str] = {}
        for mode in modes:
            if isinstance(mode, Mapping) and isinstance(mode.get("id"), str) \
                    and mode.get("role") in FM_FAMILIES:
                roles[mode["id"]] = mode["role"]
        if not roles:
            return None, (f"agents:role_registry_invalid path={path}"
                          " roles_empty",)
        return roles, ()
    return None, (f"agents:role_registry_missing path={candidates[-1]}",)


# ---------------------------------------------------------------------------
# Multi-host observation layout
# ---------------------------------------------------------------------------


def discover_host_dirs(
    obs_root: Path,
) -> tuple[Mapping[str, Path] | None, tuple[str, ...]]:
    """Map host name -> stream dir for the observation at ``obs_root``.

    ``<obs>`` is a multi-host directory (per-host stream dirs as immediate
    subdirectories — the l1 mirror-tree layout) or a single-host stream dir
    (host name = the directory's own name).  ``(None, flags)`` when the
    layout matches neither shape — fail closed, never guessed.
    """
    root = Path(obs_root)
    if (root / "supervisor.jsonl").is_file() or \
            (root / "processes.jsonl").is_file():
        return {root.name: root}, ()
    hosts: dict[str, Path] = {}
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        if any((child / marker).exists() for marker in _HOST_DIR_MARKERS):
            hosts[child.name] = child
    if not hosts:
        return None, (f"agents:layout_unrecognized path={root}",)
    return hosts, ()


def peer_wire_zeek(
    home: Path, hosts: Mapping[str, Path],
    observations: Mapping[str, Observation],
) -> tuple[tuple[Path, ...], bool]:
    """(peer zeek dirs, any peer supervisor declares a zeek sensor).

    The wire capture lives on whichever host ran zeek (l1: the router);
    the home host's own dir is excluded here because the detectors read it
    through ``obs.root / 'zeek'`` unchanged.
    """
    dirs: list[Path] = []
    declared = False
    for name in sorted(hosts):
        if hosts[name] == home:
            continue
        zeek_dir = hosts[name] / "zeek"
        if zeek_dir.is_dir() and zeek_dir not in dirs:
            dirs.append(zeek_dir)
        obs = observations.get(name)
        if obs is None:
            continue
        for record in obs.supervisor:
            if record.event in ("sensor_started", "sensor_start_failed") \
                    and record.name == "zeek":
                declared = True
                break
    return tuple(dirs), declared


# ---------------------------------------------------------------------------
# Home-host resolution (the agent lookup that spans hosts)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentResolution:
    """Outcome of resolving one agent against the observation."""

    agent: AgentSpec | None
    home_host: str | None
    home_obs: Observation | None
    hosts: tuple[str, ...]
    wire_zeek_dirs: tuple[Path, ...] = ()
    wire_zeek_declared: bool = False
    #: Non-empty -> every in-scope agent unit fails closed (named flags).
    flags: tuple[str, ...] = ()


def _census_keys(obs: Observation) -> set[tuple[int, str]]:
    keys: set[tuple[int, str]] = set()
    for record in obs.processes:
        if record.event in ("process_seen", "process_changed",
                            "process_gone"):
            keys.add((record.pid, record.start_ticks))
    return keys


def _agent_tree_pids(obs: Observation) -> frozenset[int] | None:
    """The home host's agent tree: supervisor workload pid closed under the
    census first-seen-ppid fixpoint, augmented by the strace fork/clone
    parentage fixpoint (streamkit.workload_tree / streamkit.strace_children
    — the frozen fm_2_3 helpers, reused verbatim)."""
    started = next(
        (r for r in obs.supervisor if r.event == "workload_started"), None)
    if started is None or started.pid is None or started.pid < 0:
        return None
    tree: set[int] = set(streamkit.workload_tree(obs.processes, started.pid))
    children = streamkit.strace_children(obs.strace)
    changed = True
    while changed:
        changed = False
        for parent, kids in children.items():
            if parent in tree:
                for kid in kids:
                    if kid != 1 and kid not in tree:
                        tree.add(kid)
                        changed = True
    return frozenset(tree)


def resolve_agent(agent: AgentSpec, hosts: Mapping[str, Path],
                  observations: Mapping[str, Observation],
                  ) -> AgentResolution:
    """Resolve the agent's single home host and verify its declared roots
    against that host's census and workload tree.  Every unresolved or
    contradictory declaration is a named fail-closed flag — never a guess.
    """
    flags: list[str] = []
    declared_hosts = sorted(agent.roots_by_host)
    if len(declared_hosts) != 1:
        flags.append(f"agents:multi_home id={agent.id}"
                     f" hosts={declared_hosts}")
        return AgentResolution(agent=agent, home_host=None, home_obs=None,
                               hosts=tuple(sorted(hosts)), flags=tuple(flags))
    host = declared_hosts[0]
    if host not in hosts:
        flags.append(f"agents:host_missing id={agent.id} host={host}"
                     f" hosts_in_observation={sorted(hosts)}")
        return AgentResolution(agent=agent, home_host=None, home_obs=None,
                               hosts=tuple(sorted(hosts)), flags=tuple(flags))
    obs = observations[host]
    roots = agent.roots_by_host[host]
    keys = _census_keys(obs)
    tree = _agent_tree_pids(obs)

    for pid, ticks in roots.census_identities:
        if (pid, ticks) not in keys:
            flags.append(f"agents:root_absent id={agent.id} host={host}"
                         f" pid={pid}@{ticks}")
            continue
        if tree is not None and pid not in tree:
            flags.append(f"agents:root_outside_workload_tree id={agent.id}"
                         f" host={host} pid={pid}@{ticks}")

    for pattern in roots.cmdline_patterns:
        matched = sorted({
            record.pid for record in obs.processes
            if record.event in ("process_seen", "process_changed")
            and pattern.search(record.cmdline)})
        if not matched:
            flags.append(f"agents:root_pattern_unmatched id={agent.id}"
                         f" host={host} pattern={pattern.pattern!r}")
            continue
        if tree is not None and not set(matched) & tree:
            flags.append(f"agents:root_outside_workload_tree id={agent.id}"
                         f" host={host} pattern={pattern.pattern!r}"
                         f" pids={matched}")

    wire_dirs, wire_declared = peer_wire_zeek(hosts[host], hosts,
                                              observations)
    return AgentResolution(
        agent=agent, home_host=host, home_obs=obs,
        hosts=tuple(sorted(hosts)), wire_zeek_dirs=wire_dirs,
        wire_zeek_declared=wire_declared, flags=tuple(flags))


def agent_fused_observation(resolution: AgentResolution) -> Observation:
    """The agent-scoped view handed to every detector.

    Attribution planes = the home host's streams verbatim (identity-join
    planes must not mix across hosts: (pid, start_ticks) keys would
    collide).  Wire plane = the home host's zeek directory (read through
    ``obs.root`` unchanged) PLUS every peer host's zeek directory and zeek
    sensor declaration, carried by the two agent-scoped Observation fields
    the conn.log loaders consult.  Peer records never enter the fused
    streams, so no cross-host identity join can ever fire.
    """
    assert resolution.home_obs is not None
    return replace(
        resolution.home_obs,
        wire_zeek_dirs=resolution.wire_zeek_dirs,
        wire_zeek_declared=resolution.wire_zeek_declared,
    )


# ---------------------------------------------------------------------------
# Agent-tree auto-discovery (the DEFAULT measurement mode, 2026-11-11)
# ---------------------------------------------------------------------------


def discover_agents(
    hosts: Mapping[str, Path],
    observations: Mapping[str, Observation],
    roles_by_host: Mapping[str, str] | None = None,
) -> tuple[list[AgentSpec], tuple[str, ...]]:
    """Discover every agent tree across the observation's hosts.

    Per host (sorted): the supervisor workload bracket delimits the
    monitored tree (:func:`_agent_tree_pids` — the frozen workload/strace
    fixpoint); census records INSIDE that tree whose cmdline matches an
    agent census pattern (:data:`AGENT_CENSUS_PATTERNS`, the opencode-serve
    census) are the agent identities.  Identities are grouped per census
    binary name — one agent per ``(host, name)`` carrying ALL its census
    identities as roots (the l1 model: one agent session, several serve
    processes; the same grouping the fm_4.2 attacker_opencode_roots config
    used).  The agent id is ``<name>@<host>`` — deterministic, unique per
    host.

    Roles come from ``roles_by_host`` (the human-declared map keyed by the
    host's OBSERVATION DIR NAME); a host absent from the map yields role
    ``unknown`` (surfaces ``("unknown", "shared")``) — never inferred from
    the host's name.  Named flags (never guesses):
    ``agents:workload_bracket_absent host=<h>`` (no monitored bracket on
    that host) and ``agents:agent_unbracketed host=<h> pids=[...]`` (a
    census match OUTSIDE the monitored bracket is named and never
    measured).  Hosts with a bracket but no census match are the estate:
    evidence-only, silently normal.
    """
    roles = dict(roles_by_host or {})
    agents: list[AgentSpec] = []
    flags: list[str] = []
    for host in sorted(hosts):
        obs = observations[host]
        tree = _agent_tree_pids(obs)
        matches: dict[str, list[tuple[int, str]]] = {}
        unbracketed: list[int] = []
        for record in obs.processes:
            if record.event not in ("process_seen", "process_changed"):
                continue
            if not any(p.search(record.cmdline)
                       for p in AGENT_CENSUS_PATTERNS):
                continue
            if tree is None or record.pid not in tree:
                if record.pid not in unbracketed:
                    unbracketed.append(record.pid)
                continue
            name = record.name or record.cmdline.split(" ", 1)[0]
            identities = matches.setdefault(name, [])
            identity = (record.pid, record.start_ticks)
            if identity not in identities:
                identities.append(identity)
        if tree is None:
            flags.append(f"agents:workload_bracket_absent host={host}")
        if unbracketed:
            flags.append(f"agents:agent_unbracketed host={host}"
                         f" pids={sorted(unbracketed)}")
        for name in sorted(matches):
            role = roles.get(host, ROLE_UNKNOWN)
            surfaces = ((role, "shared") if role in AGENT_ROLES
                        else (ROLE_UNKNOWN, "shared"))
            agents.append(AgentSpec(
                id=f"{name}@{host}", role=role, surfaces=surfaces,
                roots_by_host={host: RootSpec(
                    census_identities=tuple(sorted(matches[name])))}))
    return agents, tuple(flags)


def _battery_results(
    agent: AgentSpec,
    resolution: AgentResolution,
    modules: list[Any],
    roles: Mapping[str, str],
    config_dir: Path | None,
    fm_filter: set[str] | None,
    undeclared_action: str,
) -> dict[str, list[UnitResult]]:
    """Run the in-scope FM battery for ONE resolved agent.

    Scope per module: registry-unknown FMs are skipped (named only when
    explicitly requested); FMs outside the agent's surfaces are skipped
    (named UNMEASURED when explicitly requested); for an agent whose home
    host has no declared role, role-scoped FMs fail closed as run-level
    UNMEASURED carrying ``agents:role_undeclared`` (``undeclared_action=
    "unmeasured"``, the auto-mode default) — only shared-surface FMs
    decide, never a guessed role.  Unit keys are agent-scoped.
    """
    assert resolution.home_obs is not None
    # Deferred import: analysis.analyze imports this module at top level.
    from .analyze import load_config

    obs = agent_fused_observation(resolution)
    results: dict[str, list[UnitResult]] = {}
    for module in modules:
        fm_id = str(module.FM_ID)
        action, unit = scope_module(fm_id, roles.get(fm_id), agent,
                                    fm_filter,
                                    undeclared_action=undeclared_action)
        if action == "skip":
            continue
        if action == "unmeasured":
            assert unit is not None
            results[fm_id] = [unit]
            continue
        cfg: Mapping[str, Any] = load_config(config_dir, module)
        units = tuple(
            replace(u, unit_key=agent_unit_key(fm_id, u.unit_key, agent.id))
            for u in module.detect(obs, cfg))
        results[fm_id] = sorted(units, key=lambda u: u.unit_key)
    return results


# ---------------------------------------------------------------------------
# Unit keys + module selection
# ---------------------------------------------------------------------------


def agent_unit_key(fm_id: str, unit_key: str, agent_id: str) -> str:
    """``FM<id>/run`` -> ``FM<id>/agent=<id>`` (the agent IS the run);
    every other unit keeps its shape inside the agent scope:
    ``FM4.2/victim=60@90`` -> ``FM4.2/agent=<id>/victim=60@90``."""
    prefix = f"{fm_id}/"
    rest = unit_key[len(prefix):] if unit_key.startswith(prefix) else unit_key
    if rest == "run":
        return f"{fm_id}/agent={agent_id}"
    return f"{fm_id}/agent={agent_id}/{rest}"


def scope_module(fm_id: str, role: str | None, agent: AgentSpec,
                 fm_filter: set[str] | None,
                 undeclared_action: str = "skip",
                 ) -> tuple[str, UnitResult | None]:
    """Role-scope one detector module for one agent.

    Returns ``(action, unit)`` with action ``"run"`` / ``"skip"`` /
    ``"unmeasured"``.  A registry-unknown FM is skipped unless explicitly
    requested (then a named UNMEASURED unit); an FM whose registry role is
    outside the agent's surfaces likewise — the directive's "defender FMs
    only measure when a defender agent is analyzed; attacker FMs only for
    attacker agents; shared for both".

    ``undeclared_action="unmeasured"`` (auto-discovery default) changes the
    out-of-surface outcome for an agent whose home host has NO declared
    role (surfaces carry ``unknown``): every role-scoped FM becomes a
    run-level UNMEASURED unit carrying ``agents:role_undeclared`` —
    fail-closed, never guessed.  Shared FMs always decide; roles for
    unknown hosts are not inferred from names.
    """
    if role is None:
        if fm_filter is not None and fm_id in fm_filter:
            return "unmeasured", UnitResult.unmeasured(
                fm_id, agent_unit_key(fm_id, f"{fm_id}/run", agent.id),
                reasons=("agent-scoped run: FM role unknown to the"
                         " fm_registry roles; failing closed",),
                integrity_flags=(f"agents:role_unknown fm={fm_id}",))
        return "skip", None
    if role not in agent.surfaces:
        if undeclared_action == "unmeasured" \
                and ROLE_UNKNOWN in agent.surfaces:
            return "unmeasured", UnitResult.unmeasured(
                fm_id, agent_unit_key(fm_id, f"{fm_id}/run", agent.id),
                reasons=("agent-scoped run: this agent's home host has no"
                         " declared role; only shared-surface FMs decide",),
                integrity_flags=(
                    f"agents:role_undeclared fm={fm_id} fm_role={role}"
                    f" agent={agent.id}",))
        if fm_filter is not None and fm_id in fm_filter:
            return "unmeasured", UnitResult.unmeasured(
                fm_id, agent_unit_key(fm_id, f"{fm_id}/run", agent.id),
                reasons=("agent-scoped run: FM family outside this agent's"
                         " declared surfaces",),
                integrity_flags=(
                    f"agents:fm_out_of_agent_scope fm={fm_id} role={role}"
                    f" agent={agent.id}"
                    f" agent_surfaces={list(agent.surfaces)}",))
        return "skip", None
    return "run", None


# ---------------------------------------------------------------------------
# The agent-scoped run (called from analysis.analyze)
# ---------------------------------------------------------------------------


def _canonical_agent_document(
    observation_dir: Path,
    pins: EnvelopePins,
    flags: tuple[StreamFlag, ...],
    results: Mapping[str, list[UnitResult]],
    agent_block: Mapping[str, Any],
) -> dict:
    """The canonical JSON document in agent mode (stable shapes/ordering;
    mirrors analyze.canonical_document plus the ``agent`` header block)."""
    return {
        "observation_dir": str(observation_dir),
        "agent": dict(agent_block),
        "pins": pins.to_dict(),
        "integrity_flags": [
            flag.to_dict() for flag in sorted(
                flags, key=lambda f: (f.stream, f.code, f.detail))
        ],
        "detectors": {
            fm_id: [unit.to_dict() for unit in results[fm_id]]
            for fm_id in sorted(results)
        },
    }


def _agent_block(
    requested_id: str,
    agent: AgentSpec | None,
    home_host: str | None,
    host_names: tuple[str, ...],
    wire_zeek_dirs: tuple[Path, ...],
    wire_zeek_declared: bool,
    flags: tuple[str, ...],
    results: Mapping[str, list[UnitResult]],
    modules: list[Any],
    roles: Mapping[str, str] | None,
) -> dict:
    """The document's ``agent`` header block (agent mode only)."""
    zeek_hosts = sorted({Path(d).parent.name for d in wire_zeek_dirs})
    run_ids = set(results)
    skipped = []
    for module in modules:
        fm_id = str(module.FM_ID)
        if fm_id in run_ids:
            continue
        reason = "not_in_fm_registry" \
            if roles is not None and fm_id not in roles \
            else "outside_agent_surfaces"
        skipped.append({"fm_id": fm_id, "reason": reason})
    return {
        "id": agent.id if agent else requested_id,
        "requested_id": requested_id,
        "role": agent.role if agent else None,
        "surfaces": list(agent.surfaces) if agent else [],
        "home_host": home_host,
        "hosts_in_observation": list(host_names),
        "wire_zeek_hosts": zeek_hosts,
        "wire_zeek_declared": wire_zeek_declared,
        "fail_closed": bool(flags),
        "flags": list(flags),
        "modules_skipped": skipped,
    }


def run_agent_scoped(
    observation_dir: Path,
    config_dir: Path | None,
    fm_filter: set[str] | None,
    agent_id: str,
    pins: EnvelopePins = DEFAULT_ENVELOPE_PINS,
    detector_modules: list[Any] | None = None,
) -> dict:
    """Load, resolve, detect, and return the single-agent-scoped document.

    ``--agent <id>``: restrict the battery to ONE agent.  The agent comes
    from the full-form registry when declared there; over the minimal
    roles form (or a combined file that does not declare the id) the
    identity auto-resolves from discovery and the role comes from the
    host map — undeclared roles keep the fail-closed semantics
    (``agents:role_undeclared`` units, shared FMs decide).
    """
    # Deferred import: analysis.analyze imports this module at top level.
    from .analyze import discover_detectors

    modules = detector_modules if detector_modules is not None \
        else discover_detectors()
    if fm_filter is not None:
        modules = [m for m in modules if str(m.FM_ID) in fm_filter]

    agents_registry = load_agents_registry(config_dir)
    roles, role_flags = load_role_registry(config_dir)
    agent = agents_registry.agents.get(agent_id)

    def emit(
        home_host: str | None,
        flags: tuple[StreamFlag, ...],
        named_flags: tuple[str, ...],
        results: Mapping[str, list[UnitResult]],
        wire_dirs: tuple[Path, ...] = (),
        wire_declared: bool = False,
        scoped_agent: AgentSpec | None = agent,
    ) -> dict:
        block = _agent_block(
            agent_id, scoped_agent, home_host,
            tuple(sorted(hosts)) if hosts else (),
            wire_dirs, wire_declared, named_flags, results, modules,
            roles if scoped_agent is not None else None)
        return _canonical_agent_document(
            Path(observation_dir), pins, flags, results, block)

    hosts, layout_flags = discover_host_dirs(Path(observation_dir))
    if hosts is None:
        return emit(None, (), layout_flags, _fail_closed(
            modules, "observation layout unrecognized", layout_flags,
            agent_id), scoped_agent=None)

    observations = {name: load_observation(path, pins)
                    for name, path in sorted(hosts.items())}

    registry_flags = agents_registry.flags_for(agent_id)
    undeclared_action = "skip"
    if agent is None:
        # A registry that loaded but does not know this id is its own
        # fail-closed reason (a file-level failure already carries its
        # named flags; a named-invalid agent carries its own).
        file_broken = any(f.startswith("agents:registry_")
                          for f in registry_flags)
        agent_named = any(
            f.startswith(f"agents:agent_invalid id={agent_id} ")
            for f in registry_flags)
        if not file_broken and not agent_named \
                and agents_registry.roles_by_host:
            # Minimal roles form: identities auto-resolve from discovery
            # (the --agent surface of the per-agent default).
            found, _ = discover_agents(hosts, observations,
                                       agents_registry.roles_by_host)
            agent = next((a for a in found if a.id == agent_id), None)
            undeclared_action = "unmeasured"
        if agent is None and not file_broken and not agent_named:
            registry_flags = registry_flags + (
                f"agents:agent_unknown id={agent_id}",)
    if agent is None:
        return emit(None, (), registry_flags, _fail_closed(
            modules, "agent not usable from the agents registry",
            registry_flags, agent_id), scoped_agent=None)

    if roles is None:
        return emit(None, (), role_flags, _fail_closed(
            modules, "FM role registry unavailable", role_flags, agent_id),
            scoped_agent=agent)

    resolution = resolve_agent(agent, hosts, observations)
    if resolution.flags:
        results: dict[str, list[UnitResult]] = {}
        for module in modules:
            fm_id = str(module.FM_ID)
            action, unit = scope_module(fm_id, roles.get(fm_id), agent,
                                        fm_filter)
            if action == "skip":
                continue
            if action == "unmeasured":
                assert unit is not None
                results[fm_id] = [unit]
                continue
            results[fm_id] = [UnitResult.unmeasured(
                fm_id, agent_unit_key(fm_id, f"{fm_id}/run", agent_id),
                reasons=("agent-scoped run failed closed: the agent's"
                         " declared attribution roots do not resolve",),
                integrity_flags=resolution.flags)]
        assert resolution.home_obs is not None or resolution.home_host is None
        home_flags = resolution.home_obs.flags \
            if resolution.home_obs is not None else ()
        return emit(resolution.home_host, home_flags,
                    resolution.flags, results,
                    resolution.wire_zeek_dirs,
                    resolution.wire_zeek_declared, scoped_agent=agent)

    results = _battery_results(agent, resolution, modules, roles,
                               config_dir, fm_filter, undeclared_action)
    obs = agent_fused_observation(resolution)
    return emit(resolution.home_host, obs.flags, (), results,
                resolution.wire_zeek_dirs, resolution.wire_zeek_declared,
                scoped_agent=agent)


def _verdict_counts(
    results: Mapping[str, list[UnitResult]],
) -> dict[str, int]:
    """PASS/FAIL/UNMEASURED counts over one agent's (or the run's) units."""
    counts = {"units": 0, "PASS": 0, "FAIL": 0, "UNMEASURED": 0}
    for units in results.values():
        for unit in units:
            counts["units"] += 1
            counts[unit.outcome.value] = counts.get(unit.outcome.value, 0) + 1
    return counts


def _named_stream_flags(names: Iterable[str]) -> tuple[StreamFlag, ...]:
    """Run-level named flags as canonical StreamFlag dicts
    (``agents:<code> <detail>`` -> stream=agents, code, detail)."""
    flags: list[StreamFlag] = []
    for named in names:
        stream, _, rest = named.partition(":")
        code, _, detail = rest.partition(" ")
        flags.append(StreamFlag(stream=stream or "agents", code=code,
                                detail=detail))
    return tuple(sorted(flags, key=lambda f: (f.stream, f.code, f.detail)))


def _auto_registry_flags(flags: tuple[str, ...]) -> tuple[str, ...]:
    """Registry file-level flags that stay NAMED in auto mode.

    In the per-agent default a missing/malformed roles map is not fatal
    (it leaves every discovered agent role ``unknown`` — the A8'
    fail-closed posture) but it must stay visible: the flags ride the
    run-level integrity flags and the summary block.
    """
    return tuple(
        f for f in flags
        if f.startswith("agents:registry_missing")
        or f.startswith("agents:registry_invalid")
        or f.startswith("agents:role_invalid"))


def run_agents_auto(
    observation_dir: Path,
    config_dir: Path | None,
    fm_filter: set[str] | None = None,
    pins: EnvelopePins = DEFAULT_ENVELOPE_PINS,
    detector_modules: list[Any] | None = None,
) -> dict:
    """The per-agent DEFAULT run (2026-11-11 HARD REQUIREMENT).

    Discovers every agent tree across the observation's hosts
    (:func:`discover_agents`), runs the full in-scope FM battery per
    agent, and returns one canonical document carrying an ``agents``
    block per discovered agent plus an aggregate ``summary``.  Every FM
    unit is keyed ``FM<id>/agent=<id>``.  Estate hosts without an agent
    census match contribute evidence only and get NO FM units.  An
    observation with no agent trees yields ZERO FM units + the
    ``agents:none_detected`` run-level flag — honest empty, never a
    per-host fallback.  A missing roles map leaves every agent role
    ``unknown``: shared FMs decide, role-scoped FMs emit run-level
    UNMEASURED ``agents:role_undeclared`` units.
    """
    # Deferred import: analysis.analyze imports this module at top level.
    from .analyze import discover_detectors

    modules = detector_modules if detector_modules is not None \
        else discover_detectors()
    if fm_filter is not None:
        modules = [m for m in modules if str(m.FM_ID) in fm_filter]

    agents_registry = load_agents_registry(config_dir)
    roles, role_flags = load_role_registry(config_dir)

    named_flags: list[str] = []
    hosts, layout_flags = discover_host_dirs(Path(observation_dir))
    named_flags.extend(layout_flags)
    named_flags.extend(_auto_registry_flags(agents_registry.flags))
    named_flags.extend(role_flags)

    host_names = tuple(sorted(hosts)) if hosts is not None else ()
    agents: list[AgentSpec] = []
    observations: dict[str, Observation] = {}
    if hosts is not None:
        observations = {name: load_observation(path, pins)
                        for name, path in sorted(hosts.items())}
        found, discovery_flags = discover_agents(
            hosts, observations, agents_registry.roles_by_host)
        named_flags.extend(discovery_flags)
        agents = list(found)

    agents_blocks: list[dict] = []
    detectors: dict[str, list[UnitResult]] = {}
    per_agent_counts: dict[str, dict[str, int]] = {}
    for agent in agents:
        resolution = resolve_agent(agent, hosts, observations)
        agent_flags = list(resolution.flags)
        if roles is None:
            # Nothing can be scoped without the FM role registry: the
            # agent is still named, every FM is honest-empty.
            results: dict[str, list[UnitResult]] = {}
            agent_flags.append(
                "agents:role_registry_missing fm scoping unavailable")
        else:
            results = _battery_results(agent, resolution, modules, roles,
                                       config_dir, fm_filter,
                                       undeclared_action="unmeasured")
        for fm_id, units in results.items():
            detectors.setdefault(fm_id, []).extend(units)
        per_agent_counts[agent.id] = {
            k: v for k, v in _verdict_counts(results).items()}
        block = _agent_block(
            agent.id, agent, resolution.home_host, host_names,
            resolution.wire_zeek_dirs, resolution.wire_zeek_declared,
            tuple(agent_flags), results, modules, roles)
        block["summary"] = dict(_verdict_counts(results))
        agents_blocks.append(block)

    if not agents:
        named_flags.append(
            "agents:none_detected no agent census match inside any"
            " supervisor workload bracket")

    for fm_id in detectors:
        detectors[fm_id].sort(key=lambda u: u.unit_key)
    total = _verdict_counts(detectors)
    measured_hosts = {b["home_host"] for b in agents_blocks
                      if b["home_host"] is not None}
    return {
        "observation_dir": str(observation_dir),
        "mode": "per_agent",
        "pins": pins.to_dict(),
        "integrity_flags": [
            flag.to_dict() for flag in _named_stream_flags(named_flags)],
        "agents": agents_blocks,
        "detectors": {
            fm_id: [unit.to_dict() for unit in detectors[fm_id]]
            for fm_id in sorted(detectors)
        },
        "summary": {
            "agents": len(agents_blocks),
            "agents_detail": dict(sorted(per_agent_counts.items())),
            "hosts_in_observation": list(host_names),
            "hosts_evidence_only": [h for h in host_names
                                    if h not in measured_hosts],
            "flags": list(named_flags),
            **{k: v for k, v in total.items()},
        },
    }


def _fail_closed(
    modules: list[Any],
    reason: str,
    named_flags: tuple[str, ...],
    agent_id: str = "",
) -> dict[str, list[UnitResult]]:
    """Every requested module becomes one run-level UNMEASURED unit
    carrying the named ``agents:`` flags (the directive's fail-closed
    semantics: agent-attributed measurement never guesses)."""
    results: dict[str, list[UnitResult]] = {}
    for module in modules:
        fm_id = str(module.FM_ID)
        who = agent_id or "?"
        results[fm_id] = [UnitResult.unmeasured(
            fm_id, agent_unit_key(fm_id, f"{fm_id}/run", who),
            reasons=(f"agent-scoped run failed closed: {reason}",),
            integrity_flags=named_flags)]
    return results


__all__ = [
    "AGENTS_REGISTRY_FILENAME",
    "AGENT_CENSUS_PATTERNS",
    "AGENT_ROLES",
    "FM_FAMILIES",
    "ROLE_UNKNOWN",
    "AgentSpec",
    "AgentsRegistry",
    "AgentResolution",
    "RootSpec",
    "agent_fused_observation",
    "agent_unit_key",
    "discover_agents",
    "discover_host_dirs",
    "load_agents_registry",
    "load_role_registry",
    "peer_wire_zeek",
    "resolve_agent",
    "run_agent_scoped",
    "run_agents_auto",
    "scope_module",
]
