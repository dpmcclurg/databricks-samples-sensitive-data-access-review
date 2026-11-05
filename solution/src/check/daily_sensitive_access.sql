-- daily_sensitive_access.sql. Last task of the daily check job, after the copies and the drift check.
-- Records one UTC day's reads of sensitive columns in sensitive_access_events, with a flag for reads by
-- stewards, and the day's views of dashboards over sensitive columns in sensitive_dashboard_views.
-- Every judgment uses SDAR's own history at the moment of the read: the column's tags, the ABAC policy in
-- force on it, and the reader's group membership. The day is yesterday (UTC), or the check_date job
-- parameter (yyyy-MM-dd) for a rerun or backfill.
-- Parameters: sdar_catalog, sdar_schema, check_date, sensitive_tag_key, sensitive_tag_values.

USE CATALOG IDENTIFIER(:sdar_catalog);
USE SCHEMA IDENTIFIER(:sdar_schema);

-- A. The day being checked: yesterday in UTC, or the check_date job parameter (yyyy-MM-dd) for a rerun.
--    The parameter arrives as a string; an empty value means yesterday.
INSERT OVERWRITE sdar_check_day
SELECT coalesce(try_cast(nullif(:check_date, '') AS DATE),
                date_sub(to_date(convert_timezone('UTC', current_timestamp())), 1)) AS d;

CREATE OR REPLACE TEMPORARY VIEW check_day AS
SELECT d FROM sdar_check_day;

-- B. Column reads that day. Any lineage row with a source is a read. A row that also has a target is a read
--    that wrote output (INSERT ... SELECT, CREATE TABLE AS SELECT), and is kept. A read that writes can
--    produce one row per target column, so keep one row per event and source column.
CREATE OR REPLACE TEMPORARY VIEW lineage_reads AS
SELECT * EXCEPT (rn) FROM (
SELECT
  cl.record_id,
  cl.event_date,
  cl.event_time,
  cl.statement_id,
  cl.created_by,
  cl.entity_type,
  cl.entity_metadata.dashboard_id    AS dashboard_id,
  cl.entity_metadata.genie_space_id  AS genie_space_id,
  cl.entity_metadata.alert_id        AS alert_id,
  cl.direct_access,
  lower(cl.source_table_full_name)   AS table_full_name,
  lower(cl.source_column_name)       AS column_name,
  cl.target_type IS NOT NULL         AS wrote_output,           -- the read also wrote somewhere
  lower(cl.target_table_full_name)   AS target_table_full_name, -- where it wrote, when it did
  false                              AS served_from_cache,
  ROW_NUMBER() OVER (
    PARTITION BY cl.event_id, cl.source_table_full_name, cl.source_column_name
    ORDER BY cl.record_id) AS rn
FROM system.access.column_lineage cl
JOIN check_day c ON cl.event_date = c.d
WHERE cl.source_type IS NOT NULL        -- something was read (with or without a write)
  AND cl.source_table_full_name IS NOT NULL
) WHERE rn = 1;

--    Reads served from the SQL warehouse result cache leave no lineage of their own. Query history names the
--    statement that computed the cached result (cache_origin_statement_id), which has lineage, so the cached
--    read gets that statement's columns with its own identity, time, and statement ID. The cache is shared
--    across identities, so the origin's identity is never used.
CREATE OR REPLACE TEMPORARY VIEW cached_reads AS
SELECT * EXCEPT (rn) FROM (
SELECT
  concat('cache:', q.statement_id, ':', cl.record_id) AS record_id,
  c.d                                 AS event_date,
  q.start_time                        AS event_time,
  q.statement_id,
  q.executed_as                       AS created_by,
  cl.entity_type,
  q.query_source.dashboard_id         AS dashboard_id,
  q.query_source.genie_space_id       AS genie_space_id,
  q.query_source.alert_id             AS alert_id,
  cl.direct_access,
  lower(cl.source_table_full_name)    AS table_full_name,
  lower(cl.source_column_name)        AS column_name,
  false                               AS wrote_output,
  CAST(NULL AS STRING)                AS target_table_full_name,
  true                                AS served_from_cache,
  ROW_NUMBER() OVER (
    PARTITION BY q.statement_id, cl.source_table_full_name, cl.source_column_name
    ORDER BY cl.record_id) AS rn
FROM system.query.history q
JOIN check_day c
  ON q.start_time >= CAST(c.d AS TIMESTAMP) AND q.start_time < CAST(date_add(c.d, 1) AS TIMESTAMP)
JOIN system.access.column_lineage cl
  ON cl.statement_id = q.cache_origin_statement_id
 AND cl.event_date BETWEEN date_sub(c.d, 2) AND c.d   -- the cached result is at most 24 hours old
WHERE q.from_result_cache
  AND q.cache_origin_statement_id <> q.statement_id
  AND cl.source_type IS NOT NULL
  AND cl.source_table_full_name IS NOT NULL
) WHERE rn = 1;

CREATE OR REPLACE TEMPORARY VIEW column_reads AS
SELECT * FROM lineage_reads UNION ALL SELECT * FROM cached_reads;

-- C. Keep reads of columns that carried a sensitive tag value at the moment of the read, from SDAR's tag
--    history. The column's and the table's other tags at that moment are kept for the policy match in part E.
CREATE OR REPLACE TEMPORARY VIEW reads_with_tags AS
SELECT r.*,
  (SELECT collect_list(named_struct('k', tv.tag_key, 'v', tv.tag_value)) FROM tag_versions tv
   WHERE tv.table_full_name = r.table_full_name AND tv.column_name = r.column_name AND NOT tv.removed
     AND tv.valid_from <= r.event_time AND (tv.valid_to IS NULL OR tv.valid_to > r.event_time)) AS column_tags,
  (SELECT collect_list(named_struct('k', tv.tag_key, 'v', tv.tag_value)) FROM tag_versions tv
   WHERE tv.table_full_name = r.table_full_name AND tv.column_name IS NULL AND NOT tv.removed
     AND tv.valid_from <= r.event_time AND (tv.valid_to IS NULL OR tv.valid_to > r.event_time)) AS table_tags
FROM column_reads r;

CREATE OR REPLACE TEMPORARY VIEW sensitive_reads AS
SELECT r.*, t.k AS tag_name, t.v AS tag_value,
       split(r.table_full_name, '[.]')[0] AS catalog_name,
       split(r.table_full_name, '[.]')[1] AS schema_name,
       split(r.table_full_name, '[.]')[2] AS table_name
FROM reads_with_tags r
LATERAL VIEW explode(r.column_tags) x AS t
WHERE t.k = :sensitive_tag_key
  AND array_contains(transform(split(:sensitive_tag_values, ','), v -> trim(v)), t.v);

-- D. Who ran the statement. executed_as is the identity whose privileges were used,
--    which is the identity the mask evaluated. Fall back to created_by if query history has no row.
CREATE OR REPLACE TEMPORARY VIEW reads_with_identity AS
SELECT
  s.*,
  q.executed_by,
  coalesce(q.executed_as, s.created_by) AS check_identity,
  q.client_application
FROM sensitive_reads s
LEFT JOIN system.query.history q
  ON q.statement_id = s.statement_id
 AND q.start_time >= CAST(s.event_date AS TIMESTAMP) - INTERVAL 1 DAY   -- bounds the scan around the
 AND q.start_time <  CAST(s.event_date AS TIMESTAMP) + INTERVAL 2 DAYS; -- day checked, so reruns work

-- E. Who was exempt from the mask on this column at the moment of the read.
--    The ABAC policy in force on the column: a column mask policy whose version was current at the read,
--    attached to the table or one of its parents, whose table condition (WHEN) and column condition (MATCH
--    COLUMNS) both match the tags at that moment. A column with a table-level mask has no ABAC mask, so its
--    stewards come from steward_group_overrides instead.
CREATE OR REPLACE TEMPORARY VIEW has_table_mask AS
SELECT DISTINCT table_full_name, column_name, snapshot_date FROM table_mask_snapshot;

CREATE OR REPLACE TEMPORARY VIEW applicable_policies AS
SELECT r.record_id, r.tag_name, r.tag_value, pv.policy_name, pv.except_principals
FROM reads_with_identity r
JOIN policy_versions pv
  ON pv.policy_type = 'POLICY_TYPE_COLUMN_MASK' AND NOT pv.deleted
 AND pv.valid_from <= r.event_time AND (pv.valid_to IS NULL OR pv.valid_to > r.event_time)
 AND (pv.on_securable_type = 'METASTORE'
   OR (pv.on_securable_type = 'CATALOG' AND pv.on_securable_fullname = r.catalog_name)
   OR (pv.on_securable_type = 'SCHEMA'  AND pv.on_securable_fullname = concat(r.catalog_name, '.', r.schema_name))
   OR (pv.on_securable_type = 'TABLE'   AND pv.on_securable_fullname = r.table_full_name))
WHERE (size(pv.table_include) = 0
       OR exists(pv.table_include, p -> exists(r.table_tags, t -> t.k = p.k AND (p.v IS NULL OR t.v = p.v))))
  AND NOT exists(pv.table_exclude, p -> exists(r.table_tags, t -> t.k = p.k AND (p.v IS NULL OR t.v = p.v)))
  AND (size(pv.column_include) = 0
       OR exists(pv.column_include, p -> exists(r.column_tags, t -> t.k = p.k AND (p.v IS NULL OR t.v = p.v))))
  AND NOT exists(pv.column_exclude, p -> exists(r.column_tags, t -> t.k = p.k AND (p.v IS NULL OR t.v = p.v)))
  AND NOT EXISTS (SELECT 1 FROM has_table_mask m
                  WHERE m.table_full_name = r.table_full_name AND m.column_name = r.column_name
                    AND m.snapshot_date BETWEEN r.event_date AND date_add(r.event_date, 1));

CREATE OR REPLACE TEMPORARY VIEW read_steward_groups AS
SELECT r.record_id, r.tag_name, r.tag_value, r.event_time, lower(r.check_identity) AS reader, steward AS steward_group
FROM reads_with_identity r
JOIN applicable_policies ap ON ap.record_id = r.record_id AND ap.tag_name = r.tag_name AND ap.tag_value = r.tag_value
LATERAL VIEW explode(ap.except_principals) e AS steward
UNION ALL
--    Steward groups named inside table-level mask functions, maintained by hand.
SELECT r.record_id, r.tag_name, r.tag_value, r.event_time, lower(r.check_identity), o.steward_group
FROM reads_with_identity r
JOIN steward_group_overrides o
  ON (o.catalog_name IS NULL OR lower(o.catalog_name) = r.catalog_name)
 AND (o.schema_name  IS NULL OR lower(o.schema_name)  = r.schema_name)
 AND (o.table_name   IS NULL OR lower(o.table_name)   = r.table_name)
 AND (o.tag_name     IS NULL OR o.tag_name  = r.tag_name)
 AND (o.tag_value    IS NULL OR o.tag_value = r.tag_value);

--    Membership at the moment of the read is the latest add or remove for that group and reader at or
--    before the read. On a tie at the same moment, the add wins, so the check errs toward flagging.
CREATE OR REPLACE TEMPORARY VIEW steward_matches AS
SELECT record_id, tag_name, tag_value, collect_set(steward_group) AS steward_groups
FROM (
  SELECT g.record_id, g.tag_name, g.tag_value, g.steward_group, m.action,
         ROW_NUMBER() OVER (
           PARTITION BY g.record_id, g.tag_name, g.tag_value, g.steward_group
           ORDER BY m.event_time DESC, m.action ASC) AS rn
  FROM read_steward_groups g
  JOIN group_membership_events m
    ON m.group_name  = g.steward_group
   AND m.member_name = g.reader
   AND m.event_time <= g.event_time

  UNION ALL

  -- A user or service principal named directly in EXCEPT is a steward without a group.
  SELECT record_id, tag_name, tag_value, steward_group, 'add' AS action, 1 AS rn
  FROM read_steward_groups
  WHERE lower(steward_group) = reader
) latest
WHERE rn = 1 AND action = 'add'
GROUP BY record_id, tag_name, tag_value;

--    Every read is kept. Reads with no steward match get is_steward = false and an empty list.
CREATE OR REPLACE TEMPORARY VIEW reads_flagged AS
SELECT
  r.*,
  sm.record_id IS NOT NULL                                     AS is_steward,
  coalesce(sm.steward_groups, CAST(array() AS ARRAY<STRING>))  AS steward_groups,
  (SELECT first(ap.policy_name) FROM applicable_policies ap
   WHERE ap.record_id = r.record_id AND ap.tag_name = r.tag_name AND ap.tag_value = r.tag_value) AS policy_name
FROM reads_with_identity r
LEFT JOIN steward_matches sm
  ON sm.record_id = r.record_id
 AND sm.tag_name  = r.tag_name
 AND sm.tag_value = r.tag_value;

-- F. Idempotent write. One row per read record and tag, so a rerun adds nothing new.
MERGE INTO sensitive_access_events t
USING (
  SELECT
    record_id, event_date, event_time, statement_id,
    table_full_name, column_name, tag_name, tag_value, wrote_output, target_table_full_name,
    check_identity, executed_by, is_steward, steward_groups, client_application,
    entity_type, dashboard_id, genie_space_id, alert_id, direct_access, served_from_cache, policy_name,
    CASE
      WHEN served_from_cache           THEN 'Served from the result cache: columns from the statement that computed the result'
      WHEN dashboard_id IS NOT NULL    THEN 'Dashboard run: see sensitive_dashboard_views for the publishing mode and viewers'
      WHEN genie_space_id IS NOT NULL  THEN 'Genie run: the asking user, unless the space follows a shared-permission dashboard'
      WHEN NOT direct_access           THEN 'Read through a view: confirm the policy evaluated the reader'
      WHEN policy_name IS NULL AND size(steward_groups) = 0
                                       THEN 'No ABAC policy in force on this column: check for a table-level mask and an override row'
      ELSE 'Direct read'
    END AS review_note,
    current_timestamp() AS loaded_at
  FROM reads_flagged
) s
ON  t.record_id = s.record_id
AND t.tag_name  = s.tag_name
AND t.tag_value = s.tag_value
WHEN NOT MATCHED THEN INSERT *;

-- G. Dashboard views. The audit log records each view of a published dashboard with the viewer's
--    identity and whether the dashboard runs on shared data permissions. request_params is a
--    map<string, string>, so credentials_embedded holds the string 'true' or 'false', not a boolean.
--    The same dashboard_id appears in the audit log, column lineage, and query history.
CREATE OR REPLACE TEMPORARY VIEW dashboard_views AS
SELECT
  a.event_date,
  a.request_params['dashboard_id']         AS dashboard_id,
  a.user_identity.email                    AS viewer,
  a.request_params['credentials_embedded'] AS credentials_embedded,
  min(a.event_time)                        AS first_view_time,
  count(*)                                 AS views
FROM system.access.audit a
JOIN check_day c ON a.event_date = c.d
WHERE a.service_name = 'dashboards'
  AND a.action_name  = 'getPublishedDashboard'
GROUP BY a.event_date, a.request_params['dashboard_id'], a.user_identity.email,
         a.request_params['credentials_embedded'];

--    Dashboards that read a sensitive column in the last 30 days. A 30-day window covers views
--    served from cached results, which do not produce a new read that day.
CREATE OR REPLACE TEMPORARY VIEW sensitive_dashboards AS
SELECT
  e.dashboard_id,
  collect_set(concat(e.table_full_name, '.', e.column_name)) AS sensitive_columns,
  bool_or(e.is_steward)                                       AS any_steward_read
FROM sensitive_access_events e
JOIN check_day c ON e.event_date >= date_sub(c.d, 30)
WHERE e.dashboard_id IS NOT NULL
GROUP BY e.dashboard_id;

MERGE INTO sensitive_dashboard_views t
USING (
  SELECT
    v.event_date, v.dashboard_id, v.viewer, v.credentials_embedded,
    -- On a shared-permission dashboard every query runs as the publisher, so a steward read means
    -- every viewer saw the publisher's unmasked view. On an individual-permission dashboard the
    -- flag would describe individual viewers instead, so it is left empty there.
    CASE WHEN v.credentials_embedded = 'true' THEN d.any_steward_read END AS runs_as_steward,
    d.sensitive_columns, v.first_view_time, v.views,
    current_timestamp() AS loaded_at
  FROM dashboard_views v
  JOIN sensitive_dashboards d ON d.dashboard_id = v.dashboard_id
) s
ON  t.event_date   = s.event_date
AND t.dashboard_id = s.dashboard_id
AND t.viewer       = s.viewer
WHEN NOT MATCHED THEN INSERT *;
