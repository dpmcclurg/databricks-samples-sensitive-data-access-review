-- Membership copy. A copy task of the daily check job, before daily_sensitive_access.sql.
-- Copies group membership changes from the audit log into group_membership_events. Reads the last
-- lookback_days days (3 daily, 365 at setup); the MERGE skips changes already copied, so reruns
-- and a missed day are safe.
-- Parameters: sdar_catalog, sdar_schema, lookback_days.

USE CATALOG IDENTIFIER(:sdar_catalog);
USE SCHEMA IDENTIFIER(:sdar_schema);

MERGE INTO group_membership_events t
USING (
  SELECT
    a.event_id                                         AS source_event_id,
    a.event_time,
    a.event_date,
    a.request_params['targetGroupName']                AS group_name,
    lower(a.request_params['targetUserName'])          AS member_name,   -- the Databricks user name
    CASE WHEN a.action_name LIKE 'add%' THEN 'add' ELSE 'remove' END AS action,
    a.request_params['groupMembershipType']            AS membership_type,
    'audit'                                            AS source,
    current_timestamp()                                AS loaded_at
  FROM system.access.audit a
  WHERE a.service_name = 'accounts'
    -- Entra ID sync logs the singular names; changes through the account SCIM API log the plural names,
    -- one event per member, without groupMembershipType.
    AND a.action_name IN ('addPrincipalToGroup', 'removePrincipalFromGroup',
                          'addPrincipalsToGroup', 'removePrincipalsFromGroup')
    AND a.event_date >= date_sub(current_date(), CAST(:lookback_days AS INT))
    AND a.request_params['targetUserName'] IS NOT NULL
    AND coalesce(a.response.status_code, 200) = 200    -- changes that were applied
) s
ON t.source_event_id = s.source_event_id
WHEN NOT MATCHED THEN INSERT *;

-- Record the run, so the health check can tell a quiet day from a copy that did not run.
INSERT INTO sdar_load_log
SELECT current_timestamp(), 'membership_events', count(*)
FROM group_membership_events
WHERE loaded_at >= current_timestamp() - INTERVAL 1 HOUR;
