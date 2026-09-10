# sms_harness — Defender Failure-Mode Measurement Lab (14 playbook FMs)

Deterministic, no-LLM measurement harness for the **14 currently-measured**
defender failure modes of the Trident playbook
(`/home/diego/SCLT/DEFENDER_FAILURE_MODES_MEASUREMENT_PLAYBOOK.md`):
FM1.1 (protected-service outage), FM1.2 (self-DoS blanket blocking), FM1.3
(wrong-direction block), FM2.1 (log deletion), FM2.2 (database data loss),
FM2.3 (capture destruction), FM3.3 (decoy data substitution), FM4.1
(ineffective containment), FM4.2 (wrong-process kill, PID-blacklist form),
FM4.5 (retry pathology), FM5.1 (injected-instruction execution), FM5.2
(injection-induced suppression, forced-utterance form), FM5.5
(injection-induced self-disarmament), FM6.1 (response refusal). Runs on the
live Docker topology `fm-defender-lab` (guarded soc_god defender on both
victim hosts, guarded coder56 attacker, slips + router capture) with
defender/attacker actions simulated by host-side scripts writing the same
trusted streams the real pipeline produces.

**Implementations removed 2026-08-27** (harness + measured results; the
playbook keeps the failure-mode definitions with the recipe intentionally
blank): FM3.1, FM3.2, FM4.3, FM4.4, FM5.4, FM6.4. **Removed entirely
(playbook included):** FM5.3, FM6.2, FM6.3, FM7.1, FM7.2, FM8.1 (families 7
and 8). FM4.2 and FM5.2 were reworked the same day — see their RESULTS
sections.

Modules (`sms/`): substrate `prober`, `differ`, `units`, `ledger`,
`scripted_defender` (with `gate=`/`ungated=` verdict-ledger mode), `ocx_tail`,
`host_capture`, `integrity`, `mutate_filter`, `run_controller`, `common`,
`verdict_ledger` (simulated guardrail gate + HMAC-chained verdict ledger),
`dbprobe` (frozen-checksum DB census), `inject_delivery` (host-executed
injection payload delivery, shared by FM5.2/FM5.5); FM analyzers
`fm11_outage`, `fm4_residual`, `canary_check` (FM5.1), `fm61_refusal`;
`fm12_selfdos`, `fm55_selfdisarm`; `fm13_wrongdir`, `fm21_logdel`,
`fm42_wrongkill` (PID-blacklist form), `fm52_suppress` (forced-utterance
form); `fm22_dbloss`, `fm23_capture`, `fm33_substitute`, `fm45_retry`.

Docs: [DESIGN.md](DESIGN.md) (v1 architecture + contracts) ·
[DESIGN2.md](DESIGN2.md) (v2 contracts) · [DESIGN3.md](DESIGN3.md) (v3
contracts + honesty rules) · [DESIGN4.md](DESIGN4.md) (v4 contracts, lane
isolation, honesty minimum set) — v2–v4 are historical contracts; the FMs
they specify that are listed as removed above no longer have
implementations · [RESULTS.md](RESULTS.md) (lab verification, per-FM
verdicts incl. a measured repeatability section, how to run) ·
[COVERAGE.md](COVERAGE.md) (honest clause-level coverage vs the playbook for
the 14 measured FMs).

v4 execution note: the v4 e2e suites were originally run to green by
**three lanes executing in parallel against the single live lab** (per-lane
run archives, globally-unique markers and in-lane restores); the lanes for
removed FMs (fm31/fm32/fm43/fm44/fm53/fm54/fm62/fm63/fm64/fm71/fm72/fm81)
were deleted with those implementations.

Quickstart (python3.12 required — default python3 on this host is 3.8):

```bash
python3.12 lab/deploy_lab.py ensure-up && python3.12 lab/deploy_lab.py verify  # lab up
python3.12 -m pytest tests/unit -q                                        # 181 unit tests
python3.12 -m pytest tests/e2e -q                                         # live tests across 14 files, no LLM
```
