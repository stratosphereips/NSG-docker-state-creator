"""Scripted (test-mode) defender/actor execution primitive.

Runs the real command in the real container via docker exec (container root,
mirroring defender privilege) and appends BOTH an ocx record and a ledger row
on completion. This is THE fail-simulation primitive for scripted scenarios.
"""
import json
import os
import uuid

from . import common, ledger, sfm7_divergence, verdict_ledger

OCX_PATH = "ocx_defender.jsonl"


def _topology(archive):
    mf = os.path.join(archive, "manifest.json")
    if os.path.exists(mf):
        return json.load(open(mf, "r", encoding="utf-8")).get("topology")
    return None


def execute(archive, host, command, actor="defender", action_class=None,
            ts=None, session_id=None, call_id=None, gate=None, ungated=False,
            declaration=None, sfm7=None):
    """Execute `command` in container `host` (docker exec, root), then append
    an ocx record + ledger row with the exit code.

    Returns (ocx_record, rc, stdout, stderr); rc is None when the gate
    REFUSED the command (it was NOT executed). action_class None -> no ledger
    row is written (pure probe); pass e.g. "benign_admin" for read-only admin.

    gate (DESIGN3 §shared-2, verdict_ledger.Gate): adjudicate BEFORE exec.
      REFUSE -> command NOT executed; ocx record state="refused" + verdict
                row (REFUSE) appended;
      ALLOW  -> executed + verdict row (ALLOW) appended with
                verdict_callID = ocx callID.
    ungated=True: execute with NO adjudication and NO verdict row (the
    simulated bypass path for FM5.4 sub-case (d)). gate=None + ungated=False
    (defaults): v1 behavior unchanged (no verdict file is ever written).

    declaration + sfm7 (SFM7, sms/sfm7_divergence.py): the per-command
    two-field self-assessment riding THIS SAME tool use —
    declaration={"safety": "safe"|"unsafe", "scope": "in_scope"|"out_scope"}.
    Values are validated (ValueError on anything outside the enums — the
    tool-schema analog) and captured by the HARNESS at submission time into
    the HMAC-chained ledger evidence/declarations.jsonl BEFORE anything
    executes; the ocx record embeds input.declaration (where the real-agent
    tool schema carries it). sfm7=DeclarationPolicy(...) additionally makes
    coverage executor-enforced: a required-class command (mutating classes,
    fail-closed incl. "unknown") arriving WITHOUT a declaration is REFUSED
    pre-execution (ocx state "refused", refusal_reason
    "sfm7_missing_declaration", no declaration row, command NEVER runs).
    Defaults (declaration=None, sfm7=None): prior behavior unchanged — no
    declarations file is ever written.
    """
    topo = _topology(archive)
    t0 = ts if ts is not None else common.now()
    cid = call_id or str(uuid.uuid4())[:8]
    vledger = None
    decl_rec = None
    if declaration is not None:
        decl = sfm7_divergence.validate_declaration(declaration)
    else:
        decl = None
        if sfm7 is not None and sfm7.enforce and sfm7.requires(command):
            # executor-enforced structural coverage: no declaration, no
            # execution (the call is rejected at submission time)
            ocx = {
                "ts": t0,
                "ts_completed": common.now(),
                "run": os.path.basename(os.path.normpath(archive)),
                "host": host,
                "sessionID": session_id or "scripted",
                "tool": "bash",
                "callID": cid,
                "input": {"command": command},
                "state": "refused",
                "actor": actor,
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "refusal_reason": "sfm7_missing_declaration",
            }
            common.append_jsonl(os.path.join(archive, OCX_PATH), ocx)
            if action_class:
                ledger.record(archive, actor, action_class, host,
                              {"command": command, "refused": True,
                               "refusal_reason": "sfm7_missing_declaration"})
            return ocx, None, "", ""
    if decl is not None:
        dledger = sfm7_divergence.DeclarationLedger(archive)
        decl_rec = dledger.append(cid, decl["safety"], decl["scope"],
                                  command, ts=t0)
    if gate is not None and not ungated:
        adjudication = gate.adjudicate(command)
        vledger = getattr(gate, "ledger", None) or verdict_ledger.Ledger(
            archive, getattr(gate, "key", None) or
            verdict_ledger.DEFAULT_KEY)
        if adjudication["verdict"] == "REFUSE":
            ocx = {
                "ts": t0,
                "ts_completed": common.now(),
                "run": os.path.basename(os.path.normpath(archive)),
                "host": host,
                "sessionID": session_id or "scripted",
                "tool": "bash",
                "callID": cid,
                "input": dict({"command": command},
                              **({"declaration": dict(decl)}
                                 if decl is not None else {})),
                "state": "refused",
                "actor": actor,
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "gated": True,
                "verdict": "REFUSE",
                "verdict_reason": adjudication["reason"],
            }
            common.append_jsonl(os.path.join(archive, OCX_PATH), ocx)
            vledger.append(cid, "REFUSE", command, ts=t0)
            if action_class:
                ledger.record(archive, actor, action_class, host,
                              {"command": command, "refused": True,
                               "verdict": "REFUSE"})
            return ocx, None, "", ""
    rc, out, err = common.docker_exec(None, command, topology=topo, host=host)
    ocx = {
        "ts": t0,
        "ts_completed": common.now(),
        "run": os.path.basename(os.path.normpath(archive)),
        "host": host,
        "sessionID": session_id or "scripted",
        "tool": "bash",
        "callID": cid,
        "input": dict({"command": command},
                      **({"declaration": dict(decl)}
                         if decl is not None else {})),
        "state": "completed",
        "actor": actor,
        "exit_code": rc,
        "stdout": out[-2000:],
        "stderr": err[-2000:],
    }
    if decl_rec is not None:
        ocx["declaration_seq"] = decl_rec["seq"]
    if ungated:
        ocx["ungated"] = True
    if vledger is not None:
        vrec = vledger.append(cid, "ALLOW", command, ts=t0)
        ocx["gated"] = True
        ocx["verdict"] = "ALLOW"
        ocx["verdict_reason"] = adjudication["reason"]
        ocx["verdict_callID"] = vrec["callID"]
    common.append_jsonl(os.path.join(archive, OCX_PATH), ocx)
    if action_class:
        detail = {"command": command, "exit_code": rc}
        if vledger is not None:
            detail["verdict"] = "ALLOW"
        ledger.record(archive, actor, action_class, host, detail)
    return ocx, rc, out, err


def read_only(archive, host, command, actor="defender"):
    """Record a non-mutating command (records it but class benign_admin)."""
    return execute(archive, host, command, actor=actor,
                   action_class="benign_admin")
