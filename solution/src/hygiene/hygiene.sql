-- Weekly hygiene checks. Each row is something a person should look at. The hygiene alert fires
-- when today's run wrote any row.
-- Parameters: sdar_catalog, sdar_schema, sensitive_tag_key, sensitive_tag_values.

USE CATALOG IDENTIFIER(:sdar_catalog);
USE SCHEMA IDENTIFIER(:sdar_schema);

CREATE TABLE IF NOT EXISTS sdar_hygiene (
  run_time TIMESTAMP,
  check    STRING,
  object   STRING,
  detail   STRING
) COMMENT 'Findings of the weekly hygiene checks.';

INSERT INTO sdar_hygiene
-- 1. A column mask policy that doesn't apply to all account users. Readers outside its TO list see real
--    values and are not flagged. Widen the TO list, or treat those readers as stewards.
SELECT current_timestamp(), 'narrow TO list', policy_key, concat('TO ', to_json(to_principals))
FROM policy_versions
WHERE valid_to IS NULL AND NOT deleted AND policy_type = 'POLICY_TYPE_COLUMN_MASK'
  AND NOT array_contains(transform(to_principals, x -> lower(x)), 'account users')

UNION ALL
-- 2. A policy condition SDAR can't read exactly (parentheses, several positive tags joined by AND, or several
--    positive tags with a negation). Review which columns it masks and add override rows if needed.
SELECT current_timestamp(), 'complex policy condition', policy_key,
       concat('MATCH ', coalesce(mask_condition, ''), ' WHEN ', coalesce(when_condition, ''))
FROM policy_versions
WHERE valid_to IS NULL AND NOT deleted AND complex_condition

UNION ALL
-- 3. A sensitive column with a table-level mask and no override row. SDAR can't see the group the mask
--    function tests, so reads by its stewards are not flagged. Add a steward_group_overrides row.
SELECT current_timestamp(), 'table-level mask without override', concat(m.table_full_name, '.', m.column_name), m.mask_name
FROM table_mask_snapshot m
JOIN tag_versions tv
  ON tv.table_full_name = m.table_full_name AND tv.column_name = m.column_name
 AND tv.valid_to IS NULL AND NOT tv.removed AND tv.tag_key = :sensitive_tag_key
 AND array_contains(transform(split(:sensitive_tag_values, ','), v -> trim(v)), tv.tag_value)
WHERE m.snapshot_date = (SELECT max(snapshot_date) FROM table_mask_snapshot)
  AND NOT EXISTS (
    SELECT 1 FROM steward_group_overrides o
    WHERE (o.catalog_name IS NULL OR lower(o.catalog_name) = split(m.table_full_name, '[.]')[0])
      AND (o.schema_name  IS NULL OR lower(o.schema_name)  = split(m.table_full_name, '[.]')[1])
      AND (o.table_name   IS NULL OR lower(o.table_name)   = split(m.table_full_name, '[.]')[2]))

UNION ALL
-- 4. A masked column with no sensitive tag. The mask protects it, but SDAR doesn't check its reads.
SELECT current_timestamp(), 'masked but not tagged sensitive', concat(m.table_full_name, '.', m.column_name), m.mask_name
FROM table_mask_snapshot m
WHERE m.snapshot_date = (SELECT max(snapshot_date) FROM table_mask_snapshot)
  AND NOT EXISTS (
    SELECT 1 FROM tag_versions tv
    WHERE tv.table_full_name = m.table_full_name AND tv.column_name = m.column_name
      AND tv.valid_to IS NULL AND NOT tv.removed AND tv.tag_key = :sensitive_tag_key
      AND array_contains(transform(split(:sensitive_tag_values, ','), v -> trim(v)), tv.tag_value));
