-- Drift check. A task of the daily check job, after the copies.
-- Compares SDAR's replayed policies and sensitive tags with the live definitions. Each difference means an
-- event was missed or arrived late, and is written to sdar_drift for the health check.
-- Parameters: sdar_catalog, sdar_schema, sensitive_tag_key.

USE CATALOG IDENTIFIER(:sdar_catalog);
USE SCHEMA IDENTIFIER(:sdar_schema);

INSERT INTO sdar_drift
WITH replayed AS (
  SELECT policy_key, array_sort(transform(except_principals, x -> lower(x))) AS except_list,
         array_sort(transform(to_principals, x -> lower(x))) AS to_list
  FROM policy_versions WHERE valid_to IS NULL AND NOT deleted
),
live AS (
  SELECT concat_ws('|', upper(on_securable_type),
                   lower(coalesce(concat_ws('.', catalog_name, schema_name, securable_name), '')), policy_name) AS policy_key,
         array_sort(transform(except_principals, x -> lower(x))) AS except_list,
         array_sort(transform(to_principals, x -> lower(x))) AS to_list
  FROM system.information_schema.abac_policy_definitions
)
SELECT current_timestamp(), 'policy', coalesce(r.policy_key, l.policy_key),
       CASE WHEN r.policy_key IS NULL THEN 'live policy has no SDAR history'
            WHEN l.policy_key IS NULL THEN 'SDAR history shows a policy that no longer exists'
            ELSE concat('EXCEPT or TO differs: SDAR ', to_json(r.except_list), ' live ', to_json(l.except_list)) END
FROM replayed r FULL OUTER JOIN live l ON r.policy_key = l.policy_key
WHERE r.policy_key IS NULL OR l.policy_key IS NULL OR r.except_list <> l.except_list OR r.to_list <> l.to_list

UNION ALL

SELECT current_timestamp(), 'tag', coalesce(r.col, l.col),
       concat('sensitive tag differs: SDAR ', coalesce(r.tag_value, 'none'), ' live ', coalesce(l.tag_value, 'none'))
FROM (SELECT concat(table_full_name, '.', column_name) AS col, tag_value FROM tag_versions
      WHERE valid_to IS NULL AND NOT removed AND column_name IS NOT NULL AND tag_key = :sensitive_tag_key) r
FULL OUTER JOIN (
      SELECT lower(concat_ws('.', catalog_name, schema_name, table_name, column_name)) AS col, tag_value
      FROM system.information_schema.column_tags WHERE tag_name = :sensitive_tag_key) l
  ON r.col = l.col
WHERE r.col IS NULL OR l.col IS NULL OR coalesce(r.tag_value, '') <> coalesce(l.tag_value, '');
