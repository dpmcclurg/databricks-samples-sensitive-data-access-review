# SDAR solution bundle

This folder is SDAR: a Databricks Asset Bundle that deploys its schema, jobs, and alerts into an existing workspace. For what SDAR records and why, see the [root README](../README.md). For the one-time prerequisites and the first-run commands, see [Deploying into an existing workspace](../README.md#deploying-into-an-existing-workspace).

## Layout

```
solution/
├── databricks.yml                      Bundle settings: variables, permissions, and targets
├── resources/
│   ├── sdar.schema.yml                 SDAR's schema in an existing catalog
│   ├── sdar.jobs.yml                   The five jobs
│   └── sdar.alerts.yml                 The five SQL Alerts
└── src/
    ├── admin/grants.py                 Grants on objects SDAR doesn't own (run once by a metastore admin)
    ├── setup/tables.sql                SDAR's tables and views, and the grants on its output
    ├── copy/
    │   ├── membership_events.sql       Group membership changes from the audit log
    │   ├── policy_events.sql           ABAC policy changes, with full definitions
    │   ├── tag_events.sql              Column and table tag changes
    │   ├── table_masks.sql             Today's columns with a table-level mask
    │   └── baseline.sql                Current policies and tags that have no event
    ├── check/
    │   ├── drift.sql                   Replayed state compared with the live definitions
    │   └── daily_sensitive_access.sql  One day's reads of sensitive columns and dashboard views
    ├── hygiene/hygiene.sql             Weekly findings that need a person
    └── reconcile/reconcile_group_membership.py   Members older than the audit log
```

Every SQL file reads its catalog, schema, and settings from job parameters, so nothing in `src/` names a workspace, a catalog, or a group.

## The jobs

| Job (resource key) | Runs as | When | What it does |
|---|---|---|---|
| `sdar-admin-setup` (`sdar_admin_setup`) | The deploying metastore admin | Once, at setup | `src/admin/grants.py`: `USE` and `SELECT` on `system.access` and `system.query`, access to SDAR's catalog, and `BROWSE` and `READ METADATA` on each governed catalog. Grants only add, so a rerun is safe |
| `sdar-setup` (`sdar_setup`) | SDAR principal | Once, at setup. Safe to rerun | `src/setup/tables.sql`: creates every table and view, owned by the SDAR principal, and grants the security audience `SELECT` on the two output tables and the reconcile principal what it needs |
| `sdar-check-morning` (`sdar_check`) | SDAR principal | Daily, 06:00 in `check_timezone`. Checks yesterday (UTC) | Seven tasks, in this order: the four copies (`membership_events`, `policy_events`, `tag_events`, `table_masks`) in parallel; `baseline` after the policy and tag copies; `drift` after the baseline; `sensitive_access_check` (`daily_sensitive_access.sql`) last |
| `sdar-hygiene-weekly` (`sdar_hygiene`) | SDAR principal | Mondays, 07:00 in `check_timezone` | `src/hygiene/hygiene.sql`: policies with a TO list narrower than all account users, policy conditions SDAR can't read exactly, table-level masks without an override row, and masked columns without a sensitive tag |
| `sdar-membership-reconcile` (`sdar_reconcile`) | Reconcile principal | By hand: at setup, then quarterly | `src/reconcile/reconcile_group_membership.py`: for each steward group, reads the current members (Microsoft Graph for Entra ID groups, by the group's object ID; account SCIM for Databricks groups), adds a back-dated row for each member SDAR's history is missing, and lists members to review and groups whose names differ between Entra ID and Databricks. It never removes anyone |

The daily check's job parameters:

| Parameter | Default | Use |
|---|---|---|
| `check_date` | Empty (yesterday, UTC) | `yyyy-MM-dd` to check another day |
| `lookback_days` | `3` | Days of audit events the copies read. `365` for the first run |
| `sensitive_tag_key`, `sensitive_tag_values` | From the bundle variables | Override for one run, for example to count another tag value |

## The alerts

All run as the SDAR principal, send at most one email a day, and send nothing when they clear.

| Alert | Schedule | Fires when |
|---|---|---|
| Sensitive data read by stewards (yesterday) | Daily 07:00 | Any steward read yesterday |
| Sensitive dashboards on shared data permissions (yesterday) | Daily 07:05 | A dashboard over sensitive columns, on shared permissions, was opened yesterday |
| Steward list changed since yesterday | Daily 07:10 | A column mask policy was created, changed, or deleted yesterday |
| SDAR health check: inputs missing | Daily 07:30 | A copy didn't run, drift was found, or a steward group has no members |
| SDAR hygiene findings this week | Mondays 07:30 | The weekly hygiene job wrote any finding |

Each query returns one row with one count. To see what's behind a count, run the query from `resources/sdar.alerts.yml` with `select *` in place of the count.

## Variables

Set these in a `targets.<name>.variables` block in `databricks.yml`.

| Variable | Default | What it is |
|---|---|---|
| `sdar_catalog`, `sdar_schema` | `observability`, `security` | An existing catalog, and the schema the bundle creates in it |
| `warehouse_id` | | Serverless SQL warehouse for the SQL tasks and alerts |
| `sensitive_tag_key`, `sensitive_tag_values` | `sensitivity`, `restricted` | The governed tag that marks sensitive columns, and the values that count (comma-separated) |
| `governed_catalogs` | | Catalogs that hold sensitive data (comma-separated) |
| `security_sp_application_id` | | The SDAR principal, which runs every job and alert except the reconcile |
| `group_reader_sp_application_id` | | The reconcile principal (account admin) |
| `security_audience_group` | | The group that may read SDAR's output |
| `account_id`, `account_host` | Host: `https://accounts.azuredatabricks.net` | For the reconcile |
| `secret_scope` | `sdar` | The scope that holds the reconcile's credentials |
| `alert_user_email` | | Receives the alert emails. Or replace the subscriptions with a notification destination |
| `check_timezone` | `UTC` | Time zone of the schedules, for example `America/New_York`. The check always covers a UTC day |

## Targets

The bundle ships with two targets. `dev`, the default, pauses every schedule and alert (`presets: trigger_pause_status: PAUSED`), so jobs run only when started by hand: use it for development and for shadow mode. `prod` turns them on. Add your own targets with your variables.

The top-level `permissions` give both principals `CAN_VIEW` on the bundle's files, which a job that runs as a service principal needs to read its notebook or SQL file. They apply to every resource in the bundle, which is why the reconcile's secret scope is created outside it.
