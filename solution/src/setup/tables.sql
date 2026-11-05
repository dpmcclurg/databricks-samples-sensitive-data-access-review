-- SDAR setup: the tables SDAR writes. Runs as the SDAR service principal, which then owns them.
-- Safe to rerun: every statement is IF NOT EXISTS or OR REPLACE.
-- Parameters: sdar_catalog, sdar_schema, security_audience_group, group_reader_sp.
--
-- SDAR keeps its own copy of everything its answer depends on: group membership, ABAC policies, and tags,
-- each as a history of changes copied from the audit log, plus the reads it found. The system tables are the
-- source, not the record. They keep 365 days by default, their schema can change (the audit table is in Public
-- Preview), and deleting a workspace removes its older audit events. SDAR's tables keep the evidence for as
-- long as the organization needs it, answer "who could see this column in the clear at that moment" without
-- rescanning the system tables, and can be granted to a security audience that has no access to the system
-- catalog. See the README.

USE CATALOG IDENTIFIER(:sdar_catalog);
USE SCHEMA IDENTIFIER(:sdar_schema);

-- Steward groups named inside table-level mask functions, which the policy definitions do not show.
-- Maintained by hand. Leave it empty if every mask is an ABAC policy.
CREATE TABLE IF NOT EXISTS steward_group_overrides (
  catalog_name  STRING COMMENT 'Where the mask applies. NULL means every catalog',
  schema_name   STRING COMMENT 'NULL means every schema in the catalog',
  table_name    STRING COMMENT 'NULL means every table in the schema',
  tag_name      STRING COMMENT 'Governed tag key on the masked column',
  tag_value     STRING COMMENT 'Tag value on the masked column',
  steward_group STRING COMMENT 'Account group the mask function returns real values to',
  source_note   STRING COMMENT 'The mask function, and any extra condition it checks'
) COMMENT 'Steward groups from table-level mask functions. Maintained by hand.';

-- Every change to an ABAC policy, from the audit log, plus a baseline for policies older than the audit log.
-- policy_versions (below) replays these into the full definition in force at any moment.
CREATE TABLE IF NOT EXISTS policy_events (
  source_event_id       STRING    COMMENT 'Audit log event_id, or a generated ID for baseline rows',
  event_time            TIMESTAMP COMMENT 'When the change was applied',
  event_date            DATE,
  action                STRING    COMMENT 'create, update, delete, or baseline',
  policy_name           STRING,
  on_securable_type     STRING    COMMENT 'METASTORE, CATALOG, SCHEMA, or TABLE',
  on_securable_fullname STRING    COMMENT 'Where the policy is attached (lower case)',
  policy_type           STRING    COMMENT 'For example POLICY_TYPE_COLUMN_MASK',
  to_principals         ARRAY<STRING>,
  except_principals     ARRAY<STRING> COMMENT 'Principals exempt from the policy: the stewards',
  mask_condition        STRING    COMMENT 'MATCH COLUMNS condition of the masked column (ON COLUMN alias)',
  when_condition        STRING    COMMENT 'Table condition. NULL means every table in scope',
  update_mask           STRING    COMMENT 'Fields an update set. Fields it did not set keep their earlier values',
  actor                 STRING    COMMENT 'Who made the change',
  source                STRING    COMMENT 'audit or baseline',
  loaded_at             TIMESTAMP
) COMMENT 'ABAC policy changes with their times, from the audit log plus a one-time baseline.';

-- Every tag change on a column or a table, from the audit log, plus a baseline for tags older than the audit log.
CREATE TABLE IF NOT EXISTS tag_events (
  source_event_id STRING    COMMENT 'Audit log event_id plus the tag key, or a generated ID for baseline rows',
  event_time      TIMESTAMP,
  event_date      DATE,
  table_full_name STRING    COMMENT 'catalog.schema.table (lower case)',
  column_name     STRING    COMMENT 'Lower case. NULL for a tag on the table itself',
  tag_key         STRING,
  tag_value       STRING    COMMENT 'NULL for a key-only tag or a removal',
  action          STRING    COMMENT 'set, remove, or baseline',
  actor           STRING,
  source          STRING    COMMENT 'audit or baseline',
  loaded_at       TIMESTAMP
) COMMENT 'Column and table tag changes with their times, from the audit log plus a one-time baseline.';

-- Columns masked by a table-level mask function, one copy per UTC day. A column can't carry both a
-- table-level mask and an ABAC mask, so ABAC stewards don't apply to these columns; overrides do.
CREATE TABLE IF NOT EXISTS table_mask_snapshot (
  snapshot_date   DATE,
  table_full_name STRING,
  column_name     STRING,
  mask_name       STRING
) COMMENT 'Columns with a table-level mask, from information_schema.column_masks, per UTC day.';

-- Differences between SDAR's replayed state and the live definitions. A difference means an event was missed.
CREATE TABLE IF NOT EXISTS sdar_drift (
  check_time TIMESTAMP,
  kind       STRING    COMMENT 'policy or tag',
  object     STRING,
  detail     STRING
) COMMENT 'Drift between replayed policy and tag state and the live definitions, per check run.';

-- Every change to a group's membership, from the audit log, plus the reconcile run's starting list.
CREATE TABLE IF NOT EXISTS group_membership_events (
  source_event_id STRING    COMMENT 'Audit log event_id, or a generated ID for reconcile rows',
  event_time      TIMESTAMP COMMENT 'When Databricks applied the change',
  event_date      DATE,
  group_name      STRING,
  member_name     STRING    COMMENT 'Databricks user name or application ID (lower case), the form of executed_as',
  action          STRING    COMMENT 'add or remove',
  membership_type STRING    COMMENT 'IdentityProvider for a change synced from Entra ID',
  source          STRING    COMMENT 'audit (copied from the audit log) or reconcile (reconcile run)',
  loaded_at       TIMESTAMP
) COMMENT 'Group membership changes with their times. Membership at a moment is the latest change before it.';

-- Who is in each group now: the latest change for each group and member is an add.
-- On a tie at the same moment, the add wins, so the check errs toward flagging.
CREATE OR REPLACE VIEW group_membership_current AS
SELECT group_name, member_name, event_time AS member_since
FROM (
  SELECT group_name, member_name, action, event_time,
         ROW_NUMBER() OVER (PARTITION BY group_name, member_name
                            ORDER BY event_time DESC, action ASC) AS rn
  FROM group_membership_events
)
WHERE rn = 1 AND action = 'add';

-- One row per run of the membership copy, for the health check.
CREATE TABLE IF NOT EXISTS sdar_load_log (
  run_time   TIMESTAMP,
  task       STRING,
  rows_added BIGINT
) COMMENT 'Runs of the SDAR load tasks.';

-- The day the check runs for. One row, rewritten at the start of each run.
CREATE TABLE IF NOT EXISTS sdar_check_day (d DATE)
COMMENT 'Day checked by the current check run (yesterday, or the check_date parameter).';

-- Every read of a sensitive column, one row per lineage record and tag, with the steward flag.
CREATE TABLE IF NOT EXISTS sensitive_access_events (
  record_id              STRING        COMMENT 'system.access.column_lineage record_id',
  event_date             DATE          COMMENT 'UTC day of the read',
  event_time             TIMESTAMP,
  statement_id           STRING        COMMENT 'Join key to system.query.history',
  table_full_name        STRING,
  column_name            STRING,
  tag_name               STRING        COMMENT 'Sensitive tag key on the column at the read',
  tag_value              STRING,
  wrote_output           BOOLEAN       COMMENT 'true when the read also wrote output, for example INSERT ... SELECT',
  target_table_full_name STRING        COMMENT 'Table the read wrote to, when wrote_output is true',
  check_identity         STRING        COMMENT 'Identity that ran the read (executed_as, falling back to created_by)',
  executed_by            STRING        COMMENT 'Identity that ran the statement, as recorded in query history',
  is_steward             BOOLEAN       COMMENT 'true when check_identity was in a steward group for this tag at the read',
  steward_groups         ARRAY<STRING> COMMENT 'Steward groups that matched; empty when is_steward is false',
  client_application     STRING,
  entity_type            STRING        COMMENT 'NOTEBOOK, JOB, PIPELINE, DASHBOARD_V3, DBSQL_QUERY, and so on',
  dashboard_id           STRING,
  genie_space_id         STRING,
  alert_id               STRING,
  direct_access          BOOLEAN       COMMENT 'false when the read went through a view',
  served_from_cache      BOOLEAN       COMMENT 'true when the result cache served the read; columns come from the origin statement',
  policy_name            STRING        COMMENT 'ABAC policy that masked the column at the read; NULL for table-level masks or none',
  review_note            STRING,
  loaded_at              TIMESTAMP
) COMMENT 'Reads of sensitive columns, with whether the reader was a steward at the time of the read.';

-- Views of published dashboards that read sensitive columns, one row per viewer, dashboard, and UTC day.
CREATE TABLE IF NOT EXISTS sensitive_dashboard_views (
  event_date           DATE,
  dashboard_id         STRING,
  viewer               STRING        COMMENT 'Identity that opened the published dashboard',
  credentials_embedded STRING        COMMENT 'true: shared data permissions (queries run as the publisher). false: individual',
  runs_as_steward      BOOLEAN       COMMENT 'Shared-permission dashboards only: its sensitive reads ran as a steward',
  sensitive_columns    ARRAY<STRING> COMMENT 'Sensitive columns the dashboard read in the last 30 days',
  first_view_time      TIMESTAMP,
  views                BIGINT,
  loaded_at            TIMESTAMP
) COMMENT 'Who viewed dashboards that read sensitive columns, and how each dashboard was published.';

-- Tag predicates in a policy condition: has_tag('k') and has_tag_value('k', 'v'), negated or not.
CREATE OR REPLACE FUNCTION sdar_predicates(cond STRING, negated BOOLEAN)
RETURNS ARRAY<STRUCT<k: STRING, v: STRING>>
RETURN transform(
  filter(regexp_extract_all(coalesce(cond, ''),
           '((?i:NOT)\\s+)?has_tag(?:_value)?\\(\\s*\'[^\']*\'\\s*(?:,\\s*\'[^\']*\'\\s*)?\\)', 0),
         p -> (p RLIKE '^(?i:NOT)\\s') = negated),
  p -> named_struct('k', regexp_extract(p, '\\(\\s*\'([^\']*)\'', 1),
                    'v', nullif(regexp_extract(p, ',\\s*\'([^\']*)\'', 1), '')));

-- True when a condition is not of the form SDAR reads exactly: one or more positive predicates joined by OR,
-- or a single positive predicate with negations joined by AND NOT, and no parentheses. Such policies are
-- listed by the hygiene check for a person to review.
CREATE OR REPLACE FUNCTION sdar_condition_is_complex(cond STRING)
RETURNS BOOLEAN
RETURN cond IS NOT NULL AND (
  regexp_replace(cond, 'has_tag(?:_value)?\\([^)]*\\)', '') RLIKE '[()]'
  OR (size(sdar_predicates(cond, false)) > 1 AND size(sdar_predicates(cond, true)) > 0)
  OR (size(sdar_predicates(cond, false)) > 1 AND cond RLIKE '(?i)\\bAND\\b(?!\\s+NOT\\b)'));

-- Policy definitions over time. Each event row carries the full definition after the change: a field an
-- update did not set keeps its earlier value. valid_to is the next change (NULL for the current version).
CREATE OR REPLACE VIEW policy_versions AS
WITH ordered AS (
  SELECT *,
    concat_ws('|', on_securable_type, on_securable_fullname, policy_name) AS policy_key,
    sum(CASE WHEN action IN ('create', 'baseline') THEN 1 ELSE 0 END)
      OVER (PARTITION BY on_securable_type, on_securable_fullname, policy_name ORDER BY event_time, source_event_id) AS generation
  FROM policy_events
),
filled AS (
  SELECT policy_key, policy_name, on_securable_type, on_securable_fullname, action, event_time, actor, source,
    last_value(policy_type, true)       OVER w AS policy_type,
    last_value(to_principals, true)     OVER w AS to_principals,
    last_value(except_principals, true) OVER w AS except_principals,
    last_value(mask_condition, true)    OVER w AS mask_condition,
    CASE WHEN update_mask IS NULL OR update_mask LIKE '%when_condition%' OR action IN ('create', 'baseline')
         THEN when_condition END AS when_set,
    generation
  FROM ordered
  WINDOW w AS (PARTITION BY policy_key, generation ORDER BY event_time, source_event_id
               ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)
),
versions AS (
  SELECT f.*,
    last_value(when_set, true) OVER (PARTITION BY policy_key, generation ORDER BY event_time
                                     ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS when_condition,
    lead(event_time) OVER (PARTITION BY policy_key ORDER BY event_time) AS valid_to
  FROM filled f
)
SELECT policy_key, policy_name, on_securable_type, on_securable_fullname, policy_type, to_principals,
       except_principals, mask_condition, when_condition, event_time AS valid_from, valid_to,
       action = 'delete' AS deleted, actor, source,
       -- Tag predicates in the conditions. SDAR reads a condition as (any positive predicate) AND NOT (each
       -- negated predicate), the form the policy editor writes. Anything else is flagged as complex.
       sdar_predicates(mask_condition, false) AS column_include,
       sdar_predicates(mask_condition, true)  AS column_exclude,
       sdar_predicates(when_condition, false) AS table_include,
       sdar_predicates(when_condition, true)  AS table_exclude,
       sdar_condition_is_complex(mask_condition) OR sdar_condition_is_complex(when_condition) AS complex_condition
FROM versions;

-- Tags over time: one row per column (or table) and tag key, with the value in force between valid_from and valid_to.
CREATE OR REPLACE VIEW tag_versions AS
SELECT table_full_name, column_name, tag_key,
       CASE WHEN action = 'remove' THEN NULL ELSE tag_value END AS tag_value,
       action = 'remove' AS removed,
       event_time AS valid_from,
       lead(event_time) OVER (PARTITION BY table_full_name, coalesce(column_name, ''), tag_key
                              ORDER BY event_time, source_event_id) AS valid_to,
       actor, source
FROM tag_events;

-- Today's steward list: the EXCEPT principals of every current column mask policy, plus the overrides.
CREATE OR REPLACE VIEW steward_list_current AS
SELECT 'abac_policy' AS source, policy_name, on_securable_type, on_securable_fullname, steward,
       to_principals, complex_condition
FROM policy_versions
LATERAL VIEW explode(except_principals) e AS steward
WHERE valid_to IS NULL AND NOT deleted AND policy_type = 'POLICY_TYPE_COLUMN_MASK'
UNION ALL
SELECT 'override', source_note, 'TABLE',
       lower(concat_ws('.', catalog_name, schema_name, table_name)), steward_group, CAST(NULL AS ARRAY<STRING>), false
FROM steward_group_overrides;

-- Both output tables name the people who read sensitive data. Limit who can read them.
DECLARE OR REPLACE VARIABLE audience STRING DEFAULT concat('`', :security_audience_group, '`');
DECLARE OR REPLACE VARIABLE reader STRING DEFAULT concat('`', :group_reader_sp, '`');
EXECUTE IMMEDIATE concat('GRANT SELECT ON TABLE sensitive_access_events TO ', audience);
EXECUTE IMMEDIATE concat('GRANT SELECT ON TABLE sensitive_dashboard_views TO ', audience);

-- The reconcile reads the steward list and current membership, and adds reconcile rows. Nothing else.
EXECUTE IMMEDIATE concat('GRANT SELECT ON VIEW steward_list_current TO ', reader);
EXECUTE IMMEDIATE concat('GRANT SELECT ON VIEW group_membership_current TO ', reader);
EXECUTE IMMEDIATE concat('GRANT SELECT, MODIFY ON TABLE group_membership_events TO ', reader);
