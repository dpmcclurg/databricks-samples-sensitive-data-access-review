-- Table-level masks. A copy task of the daily check job.
-- Copies today's list of columns with a table-level mask function. ABAC policies never apply to these
-- columns, so their stewards come from steward_group_overrides. Replaces today's rows on a rerun.
-- Parameters: sdar_catalog, sdar_schema.

USE CATALOG IDENTIFIER(:sdar_catalog);
USE SCHEMA IDENTIFIER(:sdar_schema);

DELETE FROM table_mask_snapshot WHERE snapshot_date = to_date(convert_timezone('UTC', current_timestamp()));

INSERT INTO table_mask_snapshot
SELECT to_date(convert_timezone('UTC', current_timestamp())),
       lower(concat_ws('.', table_catalog, table_schema, table_name)), lower(column_name), mask_name
FROM system.information_schema.column_masks   -- privilege-aware: needs BROWSE on each governed catalog
WHERE table_catalog <> 'system';            -- the system tables' own masks
