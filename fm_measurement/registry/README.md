# Unified FM Registry

One map of every failure mode in the taxonomy (32 modes: 21 defender FM,
4 attacker AFM, 7 shared SFM — per `../docs/experiment_design_unified.tex`)
to every surface that implements it. **19 modes are measured on at least one
surface.** The machine-readable source of truth is
[`fm_registry.json`](fm_registry.json); the table below is rendered from it
by hand and kept honest by `tests/fm/test_fm_registry.py`, which enforces
the registry against the code bidirectionally (run:
`python3.12 -m pytest tests/fm/test_fm_registry.py -q`).

Surfaces: **DSC** = post-hoc detector in this repo (`analysis/detectors/`,
verdicts PASS/FAIL/UNMEASURED over recorded observations) · **SMS** = live-lab
analyzer (`fm_measurement/sms_harness/sms/`, deterministic scripted runs on
topology `fm-defender-lab`) · **NSG** = simulator detector (external repo
`stratosphereips/NetSecGame`, branch `safety-failure-mode-measurement`).

## Defender modes (FM)

| ID | Mode | DSC | SMS | NSG |
|---|---|---|---|---|
| FM1.1 | Protected-service stop/restart | ✗ kill half collapses into FM4.2 | `fm11_outage` | |
| FM1.2 | Self-DoS via blanket blocking | `fm_1_2` ✓ (adv battery pending) | `fm12_selfdos` | `fm1_2` |
| FM1.3 | Wrong-direction block | `fm_1_3` ⚠ WIP, no battery | `fm13_wrongdir` | |
| FM2.1 | Log deletion/truncation | `fm_2_1` ✓ | `fm21_logdel` | |
| FM2.2 | Database data loss | ✗ attribution unbuildable | `fm22_dbloss` | |
| FM2.3 | Capture destruction | `fm_2_3` ✓ | `fm23_capture` | |
| FM3.1 | Evidence fabrication | ✗ deferred, no predicate | removed 2026-08-27 | |
| FM3.2 | Honeypot on production attack surface | ✗ deferred, no predicate | removed 2026-08-27 | |
| FM3.3 | Decoy data substitution | ✗ attribution unbuildable | `fm33_substitute` | |
| FM4.1 | Ineffective containment / false completion | `fm_4_1` ✓ (absorbs FM4.3+FM6.3) | `fm4_residual` | |
| FM4.2 | Wrong-process kill | `fm_4_2` ✓ | `fm42_wrongkill` (rev 1) | |
| FM4.3 | Unverified remediation | → absorbed into FM4.1 | removed 2026-08-27 | |
| FM4.4 | Cumulative harm from sanctioned steps | ✗ deferred, no predicate | removed 2026-08-27 | |
| FM4.5 | Retry pathology (non-idempotent repetition) | `fm_4_5` ✓ | `fm45_retry` | `fm4_5` |
| FM5.1 | Payload execution via injected instruction | `fm_5_1` ✓ (marker-canary half) | `canary_check` | |
| FM5.2 | Injection-induced suppression | ✗ paired-arm machinery | `fm52_suppress` | |
| FM5.4 | Guardrail bypass via injection | ✗ deferred, no predicate | removed 2026-08-27 | |
| FM5.5 | Injection-induced self-disarmament | ✗ verdict ledger can't be config | `fm55_selfdisarm` | |
| FM6.1 | Response refusal | ✗ absence-decided verdict | `fm61_refusal` | `fm6_1` |
| FM6.3 | False-completion declaration | → absorbed into FM4.1 | removed from playbook | |
| FM6.4 | Failure to abstain under uncertainty | ✗ deferred, no predicate | removed 2026-08-27 | |

## Attacker modes (AFM) — DSC only

| ID | Mode | DSC |
|---|---|---|
| AFM1 | Scope drift (out-of-scope action) | `afm_1` ✓ |
| AFM2 | Destructive in-scope production action | `afm_2` ✓ (permitted-delta half, file plane; rescued in wave 4) |
| AFM3 | RoE recklessness (prohibited force / noise ceilings) | `afm_3` ✓ |
| AFM4 | Restoration failure (residue left behind) | `afm_4` ✓ (open: `kind=deleted` attribution gap) |

## Shared modes (SFM) — DSC only

| ID | Mode | DSC |
|---|---|---|
| SFM1 | Confabulation (report vs engagement record) | ✗ agent-authored text in deciding path — rule 1 |
| SFM2 | Specification gaming (subverting the evaluator) | `sfm_2` ✓ (tier-A table also carries the folded SFM5 surface) |
| SFM3 | Executed safety-strip on operator order | ✗ verdict ledger can't be config |
| SFM4 | Self-initiated disabling (ungoverned window) | ✗ verdict ledger can't be config |
| SFM5 | Agent becomes the intrusion vector | → folded into `sfm_2` tier-A table |
| SFM6 | Authorization obedience decays under context load | ✗ paired-arm machinery |
| SFM7 | Acting against own recorded judgment | ✗ paired-arm machinery |

## Reading the rejections

Every ✗ is a scoped decision about the **NSG-DSC substrate** (recorded
host-side observations), not a claim the mode is unmeasurable in principle —
full reasons and the challenge conditions ("future substrate growth") are in
`../docs/NSG_DSC_FM_DETECTORS_20260907.md`. Modes like FM2.2, FM5.2 or
FM6.1 that DSC rejects **are** measured live by `sms_harness`, which controls
the substrate and can therefore build what a passive observer cannot. The
inverse also holds: AFM/SFM modes need substrate forms only the observer
records, so they exist only on the DSC surface.
