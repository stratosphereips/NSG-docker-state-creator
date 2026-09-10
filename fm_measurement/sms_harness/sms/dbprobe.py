"""Shared DB census probe (DESIGN4 §fm22 + shared db_census; FM2.2/FM3.3).

db_census(host, tables, config) -> {table: {present, rows, checksum}}

One batched `docker exec` runs `su postgres -c "psql -d <db> -A -t -c ..."`
with ONE -c per table; each -c evaluates the FROZEN checksum formula per
spec (never edit — e2e baselines + fm22/fm33 + backup-verify all pin it):

    SELECT count(*), coalesce(md5(string_agg(
        md5(t.<pk>::text)||':'||length(t::text)||':'||t::text,
        E'\\x01' ORDER BY t.<pk>)), 'EMPTY') FROM <table> t

  - md5 per-row over (pk-hash ':' row-text-length ':' row-text), aggregated
    in PK order with a \\x01 separator, whole-file md5 on top;
  - count(*) rides along so one line answers both "rows" and "content";
  - empty table -> checksum 'EMPTY' (string_agg NULL coalesced), rows 0;
  - a missing/dropped table emits NOTHING on stdout (error on stderr) ->
    {present: False} — that absence IS the FM2.2 table_gone signal.

Config keys (all optional):
  topology      default "fm-defender-lab" (container resolution via
                common.docker_exec topology=/host= re-resolve)
  database      default "corp"
  pk_map        {table: pk_column} default {secrets: id, notes: id,
                fm_tokens: id} (DESIGN4 frozen pk map)
  exec_fn       callable(cmd) -> (rc, stdout, stderr); injectable so unit
                tests NEVER touch docker. Default wraps common.docker_exec.
  timeout       docker exec timeout (default common.DOCKER_TIMEOUT)

Also ships:
  avg_row_len(host, table, config) -> int    coalesce(round(avg(length(
              t::text))), 0) — the FM2.2 bytes_lost metric's per-row size,
              consistent with the checksum's t::text view of a row.
  db_event_id(host, table, kind) -> str      "db:<host>:<table>:<kind>" —
              the SHARED event-id space between fm22 (row_loss/table_gone)
              and fm33 (data_lost reuses fm22's row_loss id, data_substituted
              its own), so cross-FM joins are exact-string.

Live-verified on fm-defender-lab 2026-08-27 (see tests/e2e/test_fm22_e2e.py):
checksum lines "4|0f07...", DELETE FROM notes -> "0|EMPTY", missing table ->
stdout line absent + rc!=0, quoting nests through bash -lc + su -c + psql -c.
"""
import argparse
import json

from . import common

DEFAULT_TOPOLOGY = "fm-defender-lab"
DEFAULT_DATABASE = "corp"
DEFAULT_PK_MAP = {"secrets": "id", "notes": "id", "fm_tokens": "id"}

FROZEN_CHECKSUM_SQL = (
    "SELECT count(*), coalesce(md5(string_agg("
    "md5(t.{pk}::text)||':'||length(t::text)||':'||t::text, "
    "E'\\x01' ORDER BY t.{pk})), 'EMPTY') FROM {table} t")

AVG_ROW_LEN_SQL = "SELECT coalesce(round(avg(length(t::text))), 0) FROM {table} t"

# stderr signature of a dropped/missing table in a multi -c batch (verified
# live: successful -c emit stdout lines only, failing ones emit the psql
# error with the quoted relation name and NO stdout line)


def census_sql(table, pk="id"):
    """The frozen per-table checksum SQL (spec formula; do not change)."""
    return FROZEN_CHECKSUM_SQL.format(pk=pk, table=table)


def db_event_id(host, table, kind):
    """Shared fm22/fm33 db event-id space: db:<host>:<table>:<kind>."""
    return "db:%s:%s:%s" % (host, table, kind)


def _exec(host, cmd, config):
    exec_fn = (config or {}).get("exec_fn")
    if exec_fn is not None:
        return exec_fn(cmd)
    return common.docker_exec(
        None, cmd, topology=(config or {}).get("topology", DEFAULT_TOPOLOGY),
        host=host, timeout=(config or {}).get("timeout", common.DOCKER_TIMEOUT))


def db_census(host="server", tables=None, config=None):
    """Census {table: {present, rows, checksum}} via ONE batched psql exec.

    tables default = pk_map keys. Output lines align with the requested
    tables in order; when rc != 0 the tables named in relation-errors are
    marked present=False and the remaining stdout lines zip to the
    surviving tables (verified live: a failing -c prints no stdout line).
    """
    cfg = config or {}
    pk_map = dict(cfg.get("pk_map") or DEFAULT_PK_MAP)
    tables = [t for t in (tables if tables is not None else pk_map)]
    if not tables:
        return {}
    database = cfg.get("database", DEFAULT_DATABASE)
    sqls = [census_sql(t, pk_map.get(t, "id")) for t in tables]
    # quote-nesting (prober pattern): outer bash "..." for su -c, inner \" \"
    # reach psql as real quotes; SQL string literals ('...', E'\\x01') are
    # safe inside double quotes at both the bash and su-sh layers.
    inner = " ".join('-c \\"%s\\"' % s for s in sqls)
    cmd = 'su postgres -c "psql -d %s -A -t %s"' % (database, inner)
    rc, out, err = _exec(host, cmd, cfg)

    lines = [l.strip() for l in (out or "").splitlines() if l.strip()]
    # psql multi -c exit code reflects ONLY the last command (verified live:
    # [notes, nope, secrets] -> rc=0 with 2 stdout lines + a relation error
    # for nope on stderr) — so failed-table detection keys off stderr
    # relation errors REGARDLESS of rc, never the exit code alone.
    failed = set()
    for t in tables:
        if ('relation "%s" does not exist' % t) in (err or "") or \
                ('relation %s does not exist' % t) in (err or ""):
            failed.add(t)
    survivors = [t for t in tables if t not in failed]
    census = {}
    if len(lines) == len(survivors):
        pairs = zip(survivors, lines)
    elif rc == 0 and len(lines) == len(tables):
        pairs = zip(tables, lines)
    else:
        # cannot align stdout to tables (partial output without a decodable
        # per-table error) — every table becomes present=False with the rc
        pairs = []
        for t in tables:
            census[t] = {"present": False, "rows": None, "checksum": None,
                         "err": "census unaligned: rc=%d n_lines=%d"
                                % (rc, len(lines))}
    for t, line in pairs:
        parts = line.split("|", 1)
        try:
            rows = int(parts[0])
        except (ValueError, IndexError):
            census[t] = {"present": False, "rows": None, "checksum": None,
                         "err": "unparsed census line %r" % line[:80]}
            continue
        checksum = parts[1].strip() if len(parts) > 1 else None
        census[t] = {"present": True, "rows": rows, "checksum": checksum}
    for t in failed:
        census[t] = {"present": False, "rows": None, "checksum": None,
                     "err": "relation does not exist"}
    return census


def avg_row_len(host="server", table="secrets", config=None):
    """avg(length(t::text)) for one table (FM2.2 bytes_lost per-row size)."""
    cfg = config or {}
    cmd = 'su postgres -c "psql -d %s -A -t -c \\"%s\\""' % (
        cfg.get("database", DEFAULT_DATABASE),
        AVG_ROW_LEN_SQL.format(table=table))
    rc, out, err = _exec(host, cmd, cfg)
    line = (out or "").strip().splitlines()[0].strip() \
        if (out or "").strip() else ""
    try:
        return int(float(line))
    except ValueError:
        return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="sms.dbprobe",
        description="corp DB census (frozen per-table checksum formula)")
    ap.add_argument("--host", default="server")
    ap.add_argument("--tables", nargs="*", default=None)
    ap.add_argument("--database", default=DEFAULT_DATABASE)
    ap.add_argument("--topology", default=DEFAULT_TOPOLOGY)
    ap.add_argument("--avg-row-len", default=None, metavar="TABLE",
                    help="also print avg row length for TABLE")
    args = ap.parse_args(argv)
    cfg = {"database": args.database, "topology": args.topology}
    census = db_census(args.host, args.tables, cfg)
    res = {"census": census}
    if args.avg_row_len:
        res["avg_row_len"] = avg_row_len(args.host, args.avg_row_len, cfg)
    print(json.dumps(res, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
