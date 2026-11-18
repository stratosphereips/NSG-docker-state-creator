\set ON_ERROR_STOP on
BEGIN;

CREATE SCHEMA nsg_fm33;
REVOKE ALL ON SCHEMA nsg_fm33 FROM PUBLIC;

CREATE TABLE nsg_fm33.tables (
    relation oid PRIMARY KEY REFERENCES nsg_fm22.protected_tables,
    key_columns name[] NOT NULL
);
CREATE TABLE nsg_fm33.sequences (relation oid PRIMARY KEY, sequence_name text UNIQUE NOT NULL);
CREATE TABLE nsg_fm33.changes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
    relation oid NOT NULL REFERENCES nsg_fm33.tables,
    operation text NOT NULL,
    login_role name NOT NULL DEFAULT session_user,
    backend_pid integer NOT NULL DEFAULT pg_backend_pid(),
    backend_start timestamptz NOT NULL DEFAULT nsg_fm22.session_start(),
    before_rows jsonb NOT NULL DEFAULT '{}',
    after_rows jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON nsg_fm33.changes (xid);

CREATE FUNCTION nsg_fm33.primary_key(target oid) RETURNS name[]
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT array_agg(a.attname ORDER BY k.position)
    FROM pg_constraint AS c
    CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, position)
    JOIN pg_attribute AS a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
    WHERE c.conrelid = target AND c.contype = 'p';
$$;

CREATE FUNCTION nsg_fm33.row_hash_query(source text, key_columns name[]) RETURNS text
LANGUAGE plpgsql SET search_path = pg_catalog, nsg_fm33, pg_temp AS $$
DECLARE
    fields text;
BEGIN
    SELECT string_agg(format('t.%I', value), ', ' ORDER BY ordinal)
      INTO fields FROM unnest(key_columns) WITH ORDINALITY AS k(value, ordinal);
    RETURN format(
        'SELECT coalesce(jsonb_object_agg(encode(sha256(record_send(ROW(%s))), ''hex''),
                 encode(sha256(record_send(t.*)), ''hex'')), ''{}''::jsonb) FROM %s AS t',
        fields, source);
END;
$$;

CREATE FUNCTION nsg_fm33.covered(target oid, keys name[]) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, nsg_fm33, pg_temp AS $$
    SELECT nsg_fm22.covered(target)
        AND nsg_fm33.primary_key(target) IS NOT DISTINCT FROM keys
        AND (SELECT count(*) FROM pg_trigger
             WHERE tgrelid = target AND tgenabled = 'A' AND tgqual IS NULL AND tgnargs = 0
               AND tgfoid = to_regprocedure('nsg_fm33.record_change()')
               AND (tgname, tgtype, coalesce(tgoldtable::text, ''), coalesce(tgnewtable::text, '')) IN (
                   ('nsg_fm33_insert', 4, '', 'new_rows'),
                   ('nsg_fm33_update', 16, 'old_rows', 'new_rows'),
                   ('nsg_fm33_delete', 8, 'old_rows', ''),
                   ('nsg_fm33_truncate', 34, '', '')
               )) = 4;
$$;

CREATE FUNCTION nsg_fm33.record_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, nsg_fm33, pg_temp SET row_security = off AS $$
DECLARE
    keys name[];
    old_hashes jsonb := '{}';
    new_hashes jsonb := '{}';
BEGIN
    SELECT key_columns INTO keys FROM nsg_fm33.tables WHERE relation = TG_RELID;
    IF keys IS NULL OR NOT nsg_fm33.covered(TG_RELID, keys) THEN
        INSERT INTO nsg_fm33.changes (relation, operation) VALUES (TG_RELID, 'coverage_gap');
        RETURN NULL;
    END IF;
    IF TG_OP = 'TRUNCATE' THEN
        EXECUTE nsg_fm33.row_hash_query(format('ONLY %s', TG_RELID::regclass), keys) INTO old_hashes;
    ELSIF TG_OP IN ('DELETE', 'UPDATE') THEN
        EXECUTE nsg_fm33.row_hash_query('old_rows', keys) INTO old_hashes;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        EXECUTE nsg_fm33.row_hash_query('new_rows', keys) INTO new_hashes;
    END IF;
    IF old_hashes <> new_hashes THEN
        INSERT INTO nsg_fm33.changes (relation, operation, before_rows, after_rows)
        VALUES (TG_RELID, lower(TG_OP), old_hashes, new_hashes);
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION nsg_fm33.protect(target regclass) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, nsg_fm33, pg_temp AS $$
DECLARE
    keys name[];
    action text;
BEGIN
    EXECUTE format('LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE', target);
    IF EXISTS (SELECT FROM nsg_fm33.tables WHERE relation = target) THEN
        RETURN;
    END IF;
    PERFORM nsg_fm22.protect(target);
    keys := nsg_fm33.primary_key(target);
    IF keys IS NULL THEN
        RAISE EXCEPTION 'FM3.3 requires a primary key: %', target;
    END IF;
    EXECUTE format('CREATE TRIGGER nsg_fm33_insert AFTER INSERT ON %s REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION nsg_fm33.record_change()', target);
    EXECUTE format('CREATE TRIGGER nsg_fm33_update AFTER UPDATE ON %s REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION nsg_fm33.record_change()', target);
    EXECUTE format('CREATE TRIGGER nsg_fm33_delete AFTER DELETE ON %s REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION nsg_fm33.record_change()', target);
    EXECUTE format('CREATE TRIGGER nsg_fm33_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION nsg_fm33.record_change()', target);
    FOREACH action IN ARRAY ARRAY['insert', 'update', 'delete', 'truncate'] LOOP
        EXECUTE format('ALTER TABLE %s ENABLE ALWAYS TRIGGER %I', target, 'nsg_fm33_' || action);
    END LOOP;
    INSERT INTO nsg_fm33.tables VALUES (target, keys);
END;
$$;

CREATE FUNCTION nsg_fm33.protect_sequence(target regclass) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, nsg_fm33, pg_temp AS $$
BEGIN
    INSERT INTO nsg_fm33.sequences (relation, sequence_name)
    SELECT c.oid, format('%I.%I', n.nspname, c.relname)
      FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
     WHERE c.oid = target AND c.relkind = 'S' AND c.relpersistence = 'p'
    ON CONFLICT (relation) DO NOTHING;
    IF NOT EXISTS (SELECT FROM nsg_fm33.sequences WHERE relation = target) THEN
        RAISE EXCEPTION 'FM3.3 requires a persistent sequence: %', target;
    END IF;
END;
$$;

CREATE FUNCTION nsg_fm33.record_coverage_gap() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, nsg_fm33, pg_temp AS $$
BEGIN
    INSERT INTO nsg_fm33.changes (relation, operation)
    SELECT t.relation, 'coverage_gap' FROM nsg_fm33.tables AS t
    JOIN pg_class AS c ON c.oid = t.relation
    WHERE NOT nsg_fm33.covered(t.relation, t.key_columns);
END;
$$;

CREATE FUNCTION nsg_fm33.capture(previous_snapshot pg_snapshot) RETURNS jsonb
LANGUAGE plpgsql SET search_path = pg_catalog, nsg_fm33, pg_temp SET row_security = off AS $$
DECLARE
    census jsonb := nsg_fm22.capture(previous_snapshot);
    registered record;
    tables jsonb := '{}';
    sequences jsonb := '{}';
    events jsonb := '[]';
    hashes jsonb;
    sequence_state jsonb;
BEGIN
    FOR registered IN
        SELECT t.*, p.table_name FROM nsg_fm33.tables AS t
        JOIN nsg_fm22.protected_tables AS p USING (relation)
    LOOP
        hashes := NULL;
        IF nsg_fm33.covered(registered.relation, registered.key_columns) THEN
            EXECUTE nsg_fm33.row_hash_query(format('ONLY %s', registered.relation::regclass),
                                           registered.key_columns) INTO hashes;
        END IF;
        tables := tables || jsonb_build_object(registered.table_name, hashes);
    END LOOP;
    FOR registered IN SELECT s.*, c.oid IS NOT NULL AS present FROM nsg_fm33.sequences AS s
        LEFT JOIN pg_class AS c ON c.oid = s.relation AND c.relkind = 'S'
    LOOP
        sequence_state := NULL;
        IF registered.present THEN
            EXECUTE format('SELECT jsonb_build_array(last_value::text, is_called) FROM %s',
                           registered.relation::regclass) INTO sequence_state;
        END IF;
        sequences := sequences || jsonb_build_object(registered.sequence_name, sequence_state);
    END LOOP;
    IF previous_snapshot IS NOT NULL THEN
        SELECT coalesce(jsonb_agg(jsonb_build_object(
            'id', c.id, 'xid', c.xid::text, 'table', p.table_name,
            'operation', c.operation, 'login_role', c.login_role,
            'backend_pid', c.backend_pid, 'backend_start', c.backend_start,
            'before', c.before_rows, 'after', c.after_rows) ORDER BY c.id), '[]')
        INTO events FROM nsg_fm33.changes AS c
        JOIN nsg_fm22.protected_tables AS p USING (relation)
        WHERE c.xid >= pg_snapshot_xmin(previous_snapshot)
          AND NOT pg_visible_in_snapshot(c.xid, previous_snapshot);
    END IF;
    RETURN census || jsonb_build_object('fm33', jsonb_build_object(
        'version', 1, 'tables', tables, 'sequences', sequences, 'changes', events,
        'coverage_trigger', EXISTS (
            SELECT FROM pg_event_trigger WHERE evtname = 'nsg_fm33_coverage'
              AND evtenabled = 'A' AND evtevent = 'ddl_command_end'
              AND evtfoid = 'nsg_fm33.record_coverage_gap()'::regprocedure
        )));
END;
$$;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA nsg_fm33 FROM PUBLIC;
CREATE EVENT TRIGGER nsg_fm33_coverage ON ddl_command_end EXECUTE FUNCTION nsg_fm33.record_coverage_gap();
ALTER EVENT TRIGGER nsg_fm33_coverage ENABLE ALWAYS;
COMMIT;
