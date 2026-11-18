\set ON_ERROR_STOP on
BEGIN;

CREATE SCHEMA nsg_fm22;
REVOKE ALL ON SCHEMA nsg_fm22 FROM PUBLIC;

CREATE TABLE nsg_fm22.installation (id uuid PRIMARY KEY DEFAULT gen_random_uuid());
INSERT INTO nsg_fm22.installation DEFAULT VALUES;

CREATE TABLE nsg_fm22.protected_tables (
    relation oid PRIMARY KEY,
    table_name text NOT NULL UNIQUE
);

CREATE FUNCTION nsg_fm22.session_start() RETURNS timestamptz
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT backend_start FROM pg_stat_activity WHERE pid = pg_backend_pid();
$$;

CREATE TABLE nsg_fm22.events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
    relation oid NOT NULL REFERENCES nsg_fm22.protected_tables,
    operation text NOT NULL,
    login_role name NOT NULL DEFAULT session_user,
    backend_pid integer NOT NULL DEFAULT pg_backend_pid(),
    backend_start timestamptz NOT NULL DEFAULT nsg_fm22.session_start(),
    row_delta bigint NOT NULL DEFAULT 0,
    checksum_delta numeric NOT NULL DEFAULT 0
);
CREATE INDEX ON nsg_fm22.events (xid);

-- Rendering values in a security-definer function must not invoke output or
-- JSON cast functions provided by the owner of an observed table.
CREATE FUNCTION nsg_fm22.supported(relation oid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, nsg_fm22, pg_temp AS $$
    SELECT EXISTS (
        SELECT FROM pg_class
        WHERE oid = relation AND relkind = 'r' AND relpersistence = 'p' AND NOT relispartition
    ) AND NOT EXISTS (
        SELECT FROM pg_inherits WHERE inhrelid = relation OR inhparent = relation
    ) AND NOT EXISTS (
        SELECT FROM pg_attribute AS a JOIN pg_type AS t ON t.oid = a.atttypid
        LEFT JOIN pg_type AS element ON element.oid = t.typelem
        WHERE a.attrelid = relation AND a.attnum > 0 AND NOT a.attisdropped
          AND (t.typnamespace <> 'pg_catalog'::regnamespace OR t.oid >= 16384
               OR t.typtype NOT IN ('b', 'r', 'm') OR t.typsend = 0 OR element.typsend = 0)
    );
$$;

-- Additive SHA-256 fingerprints let the reader reconcile a snapshot with
-- multiple concurrent statements, including duplicate rows and equal counts.
-- Only totals reach the archive. The four signed words form a base-2^64 value.
CREATE FUNCTION nsg_fm22.row_token(value bytea) RETURNS numeric
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT ('x' || substr(digest, 1, 16))::bit(64)::bigint * (radix * radix * radix)
             + ('x' || substr(digest, 17, 16))::bit(64)::bigint * (radix * radix)
             + ('x' || substr(digest, 33, 16))::bit(64)::bigint * radix
             + ('x' || substr(digest, 49, 16))::bit(64)::bigint
    FROM (SELECT encode(sha256(value), 'hex') AS digest,
                 18446744073709551616::numeric AS radix) AS values_to_hash;
$$;

CREATE FUNCTION nsg_fm22.tally(relation oid) RETURNS TABLE (rows bigint, checksum numeric)
LANGUAGE plpgsql SET search_path = pg_catalog, nsg_fm22, pg_temp AS $$
BEGIN
    RETURN QUERY EXECUTE format(
        'SELECT count(*), coalesce(sum(nsg_fm22.row_token(record_send(t.*))), 0) FROM ONLY %s AS t',
        relation::regclass);
END;
$$;

CREATE FUNCTION nsg_fm22.record_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, nsg_fm22, pg_temp
SET row_security = off AS $$
DECLARE
    old_count bigint := 0;
    new_count bigint := 0;
    old_sum numeric := 0;
    new_sum numeric := 0;
BEGIN
    IF NOT nsg_fm22.supported(TG_RELID) THEN
        INSERT INTO nsg_fm22.events (relation, operation) VALUES (TG_RELID, 'coverage_gap');
        RETURN NULL;
    END IF;
    IF TG_OP = 'TRUNCATE' THEN
        SELECT rows, checksum INTO old_count, old_sum FROM nsg_fm22.tally(TG_RELID);
    ELSIF TG_OP IN ('DELETE', 'UPDATE') THEN
        SELECT count(*), coalesce(sum(nsg_fm22.row_token(record_send(t.*))), 0)
            INTO old_count, old_sum FROM old_rows AS t;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        SELECT count(*), coalesce(sum(nsg_fm22.row_token(record_send(t.*))), 0)
            INTO new_count, new_sum FROM new_rows AS t;
    END IF;
    IF old_count <> new_count OR old_sum <> new_sum THEN
        INSERT INTO nsg_fm22.events (relation, operation, row_delta, checksum_delta)
        VALUES (TG_RELID, lower(TG_OP), new_count - old_count, new_sum - old_sum);
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION nsg_fm22.covered(relation oid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, nsg_fm22, pg_temp AS $$
    SELECT nsg_fm22.supported(relation)
       AND (SELECT count(*) FROM pg_trigger
            WHERE tgrelid = relation AND tgenabled = 'A'
              AND tgfoid = 'nsg_fm22.record_change()'::regprocedure
              AND tgqual IS NULL AND tgnargs = 0 AND NOT tgisinternal
              AND (tgname, tgtype, coalesce(tgoldtable::text, ''), coalesce(tgnewtable::text, '')) IN (
                ('nsg_fm22_insert', 4, '', 'new_rows'),
                ('nsg_fm22_delete', 8, 'old_rows', ''),
                ('nsg_fm22_update', 16, 'old_rows', 'new_rows'),
                ('nsg_fm22_truncate', 34, '', '')
              )) = 4;
$$;

CREATE FUNCTION nsg_fm22.protect(target regclass) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, nsg_fm22, pg_temp AS $$
DECLARE
    qualified_name text;
    action text;
BEGIN
    EXECUTE format('LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE', target);
    SELECT format('%I.%I', n.nspname, c.relname) INTO qualified_name
    FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
    WHERE c.oid = target AND n.nspname NOT IN ('nsg_fm22', 'pg_catalog', 'information_schema')
        AND nsg_fm22.supported(c.oid);
    IF qualified_name IS NULL THEN
        RAISE EXCEPTION 'FM2.2 requires a permanent, non-inherited ordinary table with built-in types: %', target;
    END IF;
    IF EXISTS (SELECT FROM nsg_fm22.protected_tables WHERE relation = target) THEN
        RETURN;
    END IF;
    -- Register after creating the triggers so the DDL coverage check does not
    -- report the expected intermediate installation states.
    EXECUTE format('CREATE TRIGGER nsg_fm22_insert AFTER INSERT ON %s REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION nsg_fm22.record_change()', target);
    EXECUTE format('CREATE TRIGGER nsg_fm22_delete AFTER DELETE ON %s REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION nsg_fm22.record_change()', target);
    EXECUTE format('CREATE TRIGGER nsg_fm22_update AFTER UPDATE ON %s REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION nsg_fm22.record_change()', target);
    EXECUTE format('CREATE TRIGGER nsg_fm22_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION nsg_fm22.record_change()', target);
    FOREACH action IN ARRAY ARRAY['insert', 'delete', 'update', 'truncate'] LOOP
        EXECUTE format('ALTER TABLE %s ENABLE ALWAYS TRIGGER %I', target, 'nsg_fm22_' || action);
    END LOOP;
    INSERT INTO nsg_fm22.protected_tables VALUES (target, qualified_name);
END;
$$;

CREATE FUNCTION nsg_fm22.record_drop() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, nsg_fm22, pg_temp
SET row_security = off AS $$
DECLARE
    dropped record;
    has_rows boolean;
BEGIN
    FOR dropped IN
        SELECT p.relation, bool_or(d.objsubid = 0) AS table_dropped
        FROM pg_event_trigger_dropped_objects() AS d
        JOIN nsg_fm22.protected_tables AS p ON p.relation = d.objid
        WHERE d.classid = 'pg_class'::regclass
        GROUP BY p.relation
    LOOP
        IF dropped.table_dropped THEN
            INSERT INTO nsg_fm22.events (relation, operation) VALUES (dropped.relation, 'drop_table');
        ELSE
            EXECUTE format('SELECT EXISTS (SELECT FROM ONLY %s)', dropped.relation::regclass) INTO has_rows;
            IF has_rows THEN
                INSERT INTO nsg_fm22.events (relation, operation) VALUES (dropped.relation, 'drop_column');
            END IF;
        END IF;
    END LOOP;
END;
$$;

CREATE FUNCTION nsg_fm22.record_coverage_gap() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, nsg_fm22, pg_temp AS $$
BEGIN
    INSERT INTO nsg_fm22.events (relation, operation)
    SELECT p.relation, 'coverage_gap'
    FROM nsg_fm22.protected_tables AS p JOIN pg_class AS c ON c.oid = p.relation
    WHERE NOT nsg_fm22.covered(p.relation);
END;
$$;

CREATE FUNCTION nsg_fm22.capture(previous_snapshot pg_snapshot) RETURNS jsonb
LANGUAGE plpgsql
SET search_path = pg_catalog, nsg_fm22, pg_temp
SET row_security = off AS $$
DECLARE
    capture_snapshot pg_snapshot := pg_current_snapshot();
    item record;
    counts record;
    tables jsonb := '{}'::jsonb;
    changes jsonb := '[]'::jsonb;
BEGIN
    IF current_setting('transaction_isolation') <> 'repeatable read'
        OR current_setting('transaction_read_only') <> 'on' THEN
        RAISE EXCEPTION 'capture requires a repeatable read, read-only transaction';
    END IF;
    IF pg_is_in_recovery() THEN
        RAISE EXCEPTION 'capture requires the primary PostgreSQL server';
    END IF;
    FOR item IN
        SELECT p.*, c.oid IS NOT NULL AS present
        FROM nsg_fm22.protected_tables AS p LEFT JOIN pg_class AS c ON c.oid = p.relation
    LOOP
        IF item.present AND nsg_fm22.covered(item.relation) THEN
            SELECT * INTO counts FROM nsg_fm22.tally(item.relation);
            tables := tables || jsonb_build_object(item.table_name, jsonb_build_object(
                'oid', item.relation::text, 'present', true, 'rows', counts.rows,
                'checksum', counts.checksum::text, 'covered', true));
        ELSE
            tables := tables || jsonb_build_object(item.table_name, jsonb_build_object(
                'oid', item.relation::text, 'present', item.present, 'covered', false));
        END IF;
    END LOOP;
    IF previous_snapshot IS NOT NULL THEN
        SELECT coalesce(jsonb_agg(jsonb_build_object(
            'id', e.id, 'table', p.table_name, 'operation', e.operation,
            'login_role', e.login_role, 'backend_pid', e.backend_pid, 'backend_start', e.backend_start,
            'row_delta', e.row_delta, 'checksum_delta', e.checksum_delta::text) ORDER BY e.id), '[]')
        INTO changes
        FROM nsg_fm22.events AS e JOIN nsg_fm22.protected_tables AS p USING (relation)
        WHERE e.xid >= pg_snapshot_xmin(previous_snapshot)
          AND NOT pg_visible_in_snapshot(e.xid, previous_snapshot);
    END IF;
    RETURN jsonb_build_object('installation', (SELECT id FROM nsg_fm22.installation),
        'event_triggers', (SELECT count(*) = 2 FROM pg_event_trigger WHERE evtenabled = 'A'
            AND (evtname, evtevent, evtfoid) IN (
                ('nsg_fm22_drop', 'sql_drop', 'nsg_fm22.record_drop()'::regprocedure),
                ('nsg_fm22_coverage', 'ddl_command_end', 'nsg_fm22.record_coverage_gap()'::regprocedure)
            )),
        'database', current_database(), 'snapshot', capture_snapshot::text,
        'tables', tables, 'changes', changes);
END;
$$;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA nsg_fm22 FROM PUBLIC;
CREATE EVENT TRIGGER nsg_fm22_drop ON sql_drop EXECUTE FUNCTION nsg_fm22.record_drop();
CREATE EVENT TRIGGER nsg_fm22_coverage ON ddl_command_end EXECUTE FUNCTION nsg_fm22.record_coverage_gap();
ALTER EVENT TRIGGER nsg_fm22_drop ENABLE ALWAYS;
ALTER EVENT TRIGGER nsg_fm22_coverage ENABLE ALWAYS;
COMMIT;
