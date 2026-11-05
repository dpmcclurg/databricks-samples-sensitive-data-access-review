-- Baseline. A copy task of the daily check job, after the policy and tag copies.
-- A policy or tag that hasn't changed within the audit log's window has no event. This adds one baseline row
-- for each current policy and each current tag that SDAR has no event for, dated 2000-01-01 so it counts as
-- in force before any read SDAR checks. Rows are added once; after setup this normally adds nothing.
-- Parameters: sdar_catalog, sdar_schema.

USE CATALOG IDENTIFIER(:sdar_catalog);
USE SCHEMA IDENTIFIER(:sdar_schema);

INSERT INTO policy_events
SELECT concat('baseline-', uuid()), TIMESTAMP'2000-01-01 00:00:00', DATE'2000-01-01', 'baseline',
       p.policy_name, upper(p.on_securable_type),
       lower(coalesce(concat_ws('.', p.catalog_name, p.schema_name, p.securable_name), '')),
       concat('POLICY_TYPE_', p.policy_type), p.to_principals, p.except_principals,
       regexp_replace(element_at(p.match_columns, 1), '(?i)\\s+AS\\s+\\w+\\s*$', ''), p.when_condition, CAST(NULL AS STRING),
       CAST(NULL AS STRING), 'baseline', current_timestamp()
FROM system.information_schema.abac_policy_definitions p   -- needs READ METADATA on each governed catalog
WHERE NOT EXISTS (
  SELECT 1 FROM policy_events e
  WHERE e.policy_name = p.policy_name AND e.on_securable_type = upper(p.on_securable_type)
    AND e.on_securable_fullname = lower(coalesce(concat_ws('.', p.catalog_name, p.schema_name, p.securable_name), '')));

INSERT INTO tag_events
SELECT concat('baseline-', uuid()), TIMESTAMP'2000-01-01 00:00:00', DATE'2000-01-01',
       lower(concat_ws('.', t.catalog_name, t.schema_name, t.table_name)), lower(t.column_name),
       t.tag_name, t.tag_value, 'baseline', CAST(NULL AS STRING), 'baseline', current_timestamp()
FROM (
  SELECT catalog_name, schema_name, table_name, column_name, tag_name, tag_value FROM system.information_schema.column_tags
  UNION ALL
  SELECT catalog_name, schema_name, table_name, CAST(NULL AS STRING), tag_name, tag_value FROM system.information_schema.table_tags
) t
WHERE NOT EXISTS (
  SELECT 1 FROM tag_events e
  WHERE e.table_full_name = lower(concat_ws('.', t.catalog_name, t.schema_name, t.table_name))
    AND coalesce(e.column_name, '') = coalesce(lower(t.column_name), '')
    AND e.tag_key = t.tag_name);
