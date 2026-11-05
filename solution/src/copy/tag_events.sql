-- Tag copy. A copy task of the daily check job.
-- Copies column and table tag changes from the audit log into tag_events. SQL SET TAGS and UNSET TAGS log
-- UpdateTagSubentityAssignments (columns) and UpdateTagSecurableAssignments (tables); the tag assignment API
-- logs createEntityTagAssignment and deleteEntityTagAssignment. One row per tag key changed.
-- Parameters: sdar_catalog, sdar_schema, lookback_days.

USE CATALOG IDENTIFIER(:sdar_catalog);
USE SCHEMA IDENTIFIER(:sdar_schema);

MERGE INTO tag_events t
USING (
  WITH audit AS (
    SELECT * FROM system.access.audit
    WHERE service_name = 'unityCatalog'
      AND event_date >= date_sub(current_date(), CAST(:lookback_days AS INT))
      AND coalesce(response.status_code, 200) = 200
  ),
  sql_tags AS (   -- SET TAGS and UNSET TAGS on tables and columns
    SELECT a.event_id, a.event_time, a.event_date, a.user_identity.email AS actor,
           lower(a.request_params['securable_full_name']) AS table_full_name,
           lower(a.request_params['subentity_name'])      AS column_name,
           from_json(a.request_params['changes'],
                     'STRUCT<add_tags: ARRAY<STRUCT<key: STRING, value: STRING>>, remove: ARRAY<STRING>>') AS c
    FROM audit a
    WHERE a.action_name IN ('UpdateTagSubentityAssignments', 'UpdateTagSecurableAssignments')
      AND a.request_params['securable_type'] = 'TABLE'
  ),
  api_tags AS (   -- the entity tag assignment API
    SELECT a.event_id, a.event_time, a.event_date, a.user_identity.email AS actor, a.action_name,
           from_json(a.request_params['tag_assignment'],
                     'STRUCT<entity_type: STRING, entity_name: STRING, tag_key: STRING, tag_value: STRING>') AS ta
    FROM audit a
    WHERE a.action_name IN ('createEntityTagAssignment', 'deleteEntityTagAssignment')
  )
  SELECT concat(event_id, ':', tag.key) AS source_event_id, event_time, event_date, table_full_name, column_name,
         tag.key AS tag_key, tag.value AS tag_value, 'set' AS action, actor, 'audit' AS source, current_timestamp() AS loaded_at
  FROM sql_tags LATERAL VIEW explode(c.add_tags) x AS tag
  UNION ALL
  SELECT concat(event_id, ':', k), event_time, event_date, table_full_name, column_name,
         k, CAST(NULL AS STRING), 'remove', actor, 'audit', current_timestamp()
  FROM sql_tags LATERAL VIEW explode(c.remove) x AS k
  UNION ALL
  SELECT concat(event_id, ':', ta.tag_key), event_time, event_date,
         lower(CASE WHEN lower(ta.entity_type) LIKE 'column%'
                    THEN substring_index(ta.entity_name, '.', 3) ELSE ta.entity_name END),
         lower(CASE WHEN lower(ta.entity_type) LIKE 'column%' THEN substring_index(ta.entity_name, '.', -1) END),
         ta.tag_key, ta.tag_value,
         CASE WHEN action_name = 'createEntityTagAssignment' THEN 'set' ELSE 'remove' END, actor, 'audit', current_timestamp()
  FROM api_tags
  WHERE lower(ta.entity_type) LIKE 'column%' OR lower(ta.entity_type) LIKE 'table%'
) s
ON t.source_event_id = s.source_event_id
WHEN NOT MATCHED THEN INSERT *;

INSERT INTO sdar_load_log
SELECT current_timestamp(), 'tag_events', count(*) FROM tag_events
WHERE loaded_at >= current_timestamp() - INTERVAL 1 HOUR;
