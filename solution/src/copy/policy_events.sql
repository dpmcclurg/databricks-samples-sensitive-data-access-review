-- Policy copy. A copy task of the daily check job.
-- Copies ABAC policy changes (createPolicy, updatePolicy, deletePolicy) from the audit log into policy_events,
-- with the full definition, who made the change, and when. Reads the last lookback_days days; the MERGE skips
-- events already copied, so reruns and a missed day are safe.
-- Parameters: sdar_catalog, sdar_schema, lookback_days.

USE CATALOG IDENTIFIER(:sdar_catalog);
USE SCHEMA IDENTIFIER(:sdar_schema);

MERGE INTO policy_events t
USING (
  SELECT
    a.event_id AS source_event_id,
    a.event_time,
    a.event_date,
    CASE a.action_name WHEN 'createPolicy' THEN 'create' WHEN 'updatePolicy' THEN 'update' ELSE 'delete' END AS action,
    coalesce(get_json_object(p, '$.name'), a.request_params['name']) AS policy_name,
    upper(coalesce(get_json_object(p, '$.on_securable_type'), a.request_params['on_securable_type'])) AS on_securable_type,
    lower(coalesce(get_json_object(p, '$.on_securable_fullname'), a.request_params['on_securable_fullname'], '')) AS on_securable_fullname,
    get_json_object(p, '$.policy_type') AS policy_type,
    from_json(get_json_object(p, '$.to_principals'), 'ARRAY<STRING>') AS to_principals,
    from_json(get_json_object(p, '$.except_principals'), 'ARRAY<STRING>') AS except_principals,
    -- The condition of the column the mask is applied to (ON COLUMN alias).
    coalesce(
      element_at(filter(from_json(get_json_object(p, '$.match_columns'), 'ARRAY<STRUCT<condition: STRING, alias: STRING>>'),
                        m -> m.alias = get_json_object(p, '$.column_mask.on_column')), 1).condition,
      element_at(from_json(get_json_object(p, '$.match_columns'), 'ARRAY<STRUCT<condition: STRING, alias: STRING>>'), 1).condition
    ) AS mask_condition,
    get_json_object(p, '$.when_condition') AS when_condition,
    a.request_params['update_mask'] AS update_mask,
    a.user_identity.email AS actor,
    'audit' AS source,
    current_timestamp() AS loaded_at
  FROM (SELECT *, request_params['policy_info'] AS p FROM system.access.audit) a
  WHERE a.service_name = 'unityCatalog'
    AND a.action_name IN ('createPolicy', 'updatePolicy', 'deletePolicy')
    AND a.event_date >= date_sub(current_date(), CAST(:lookback_days AS INT))
    AND coalesce(a.response.status_code, 200) = 200
) s
ON t.source_event_id = s.source_event_id
WHEN NOT MATCHED THEN INSERT *;

INSERT INTO sdar_load_log
SELECT current_timestamp(), 'policy_events', count(*) FROM policy_events
WHERE loaded_at >= current_timestamp() - INTERVAL 1 HOUR;
