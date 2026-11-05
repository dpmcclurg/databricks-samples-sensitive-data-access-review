# Sensitive Data Access Review (SDAR) for Unity Catalog

SDAR answers two questions for every day it checks:

1. **Who read data tagged as sensitive?**
2. **Which of those readers were sensitive data stewards**, meaning principals exempt from the mask on that data, at the moment of the read?

It builds that record from Unity Catalog system tables (column lineage, query history, and the audit log). Alerts notify a security audience about steward reads, about dashboards over sensitive data that run on shared permissions, and about changes to the steward list.

> **Status:** tested end to end in a test workspace (see [How SDAR was tested](#how-sdar-was-tested)). Not yet run in a production account: run it in shadow mode, with its alerts paused, before relying on it.

## What's in this repo

| Folder | What it is |
|---|---|
| `solution/` | The SDAR Databricks Asset Bundle: jobs, alerts, admin setup, and SQL. See [solution/README.md](solution/README.md). If you already have a workspace, this is the only folder you need |

## SDAR is a data product

The system tables are SDAR's sources. They are not SDAR's record. SDAR copies what it needs from them into tables it owns, keeps that copy as history, and answers every question from the copy. It is built the way a data product is built: it has an owner (the SDAR service principal), a defined audience (the security audience group), a stable schema that alerts and dashboards depend on, quality checks that run every day, and a retention period set by the organization that relies on it.

Each reason below is a dependency SDAR removes by owning its data.

| Without its own tables, SDAR would depend on | What can go wrong | What SDAR does instead |
|---|---|---|
| **Retention set outside the solution.** The audit log and lineage system tables keep 365 days by default | A review, an investigation, or a legal hold that needs more than a year of evidence finds nothing. Retention can also change without notice to the people who rely on the review | SDAR's tables keep every read, membership change, policy change, and tag change for as long as the organization's evidence policy requires |
| **Sources whose shape can change.** The audit log system table is in Public Preview, its `request_params` keys depend on the event type, and some keys are hidden from principals that aren't account admins | A schema or event name change silently breaks a report that queries the system tables directly | The copy tasks are the only code that reads the raw events. A change is fixed in one place, and the drift check reports it the next morning |
| **The life of the workspace.** Deleting a workspace removes its audit events older than 14 days | The evidence for that workspace is gone | SDAR's copy is independent of the workspace that produced the events |
| **The current state.** Tags, policies, and group membership are visible only as they are now | "Was this reader a steward when they read this column?" can't be answered once a tag, a policy, or a membership changes | SDAR keeps each as a history of changes and judges every read against the state at that moment |
| **Recomputing the past.** A report that rejoins the system tables each time it runs uses today's tags and groups | Last quarter's answer shifts whenever something changes, so the review isn't evidence | SDAR writes each read once and never rewrites it |
| **Broad access.** The system tables record activity across the whole account | Giving reviewers access to them exposes far more than sensitive reads | Reviewers get `SELECT` on SDAR's two output tables and nothing else |
| **Scanning large tables on every question.** The answer joins column lineage, query history, the audit log, tags, policies, and membership | Slow, costly, and easy to get subtly wrong each time | The join runs once a day and stores one row per read |
| **One way of learning group membership.** Under automatic identity management, no Databricks API lists the members of an Entra ID group | A design tied to one source can't fill gaps from another | The membership history accepts rows from the audit log, from Microsoft Graph, and from the Databricks SCIM API, all in one table |

## How SDAR builds its history

Membership, policies, and tags all follow one pattern:

1. **Copy the change events.** Each morning, a copy task reads the audit log and adds the day's new events to SDAR's table. A `MERGE` on the event ID skips events already copied, so reruns and missed days are safe.
2. **Add a baseline once.** Anything that hasn't changed within the audit log's window has no event. A baseline row records its current state, dated so it counts as in force before any read SDAR checks. For policies and tags the baseline comes from `information_schema`. For membership it comes from the reconcile run (Microsoft Graph for Entra ID groups, the Databricks SCIM API for Databricks groups).
3. **Replay to the moment of the read.** A view turns the events into versions with a start and an end time. The check joins each read to the version in force at that read's time.
4. **Check for drift.** Each morning, the replayed current state is compared with the live definitions. A difference means an event was missed, and the health alert reports it.

Events carry the exact time of each change and who made it, so a change at 10:00 applies to reads from 10:00, and any day can be rechecked from the events.

## The data model

| Table or view | What it holds | How it is filled | Why SDAR keeps it |
|---|---|---|---|
| `group_membership_events` | Every change to a group's membership, with its time | Daily copy from the audit log; reconcile rows for members older than the audit log | Membership at the moment of a read, past the audit log's retention |
| `group_membership_current` (view) | Who is in each group now | Replay of the events | The reconcile's comparison and the health check |
| `policy_events` | Every change to an ABAC policy, with the full definition, the actor, and the time | Daily copy from the audit log (`createPolicy`, `updatePolicy`, `deletePolicy`); baseline from `abac_policy_definitions` | Which principals were exempt from which mask at the moment of a read, and who changed it |
| `policy_versions` (view) | Each policy's full definition between two changes, with the tag predicates of its conditions | Replay of the events. An update that set only some fields keeps the others from the earlier version | The policy in force at a read |
| `tag_events` | Every tag change on a column or a table | Daily copy from the audit log; baseline from `column_tags` and `table_tags` | Whether a column was sensitive at the moment of a read, and which tags the policy conditions saw |
| `tag_versions` (view) | Each tag value between two changes | Replay of the events | The tags in force at a read |
| `table_mask_snapshot` | Columns with a table-level mask function, per day | Daily copy from `column_masks` | A column with a table-level mask has no ABAC mask, so its stewards come from the overrides |
| `steward_group_overrides` | Steward groups named inside table-level mask functions | By hand | A group tested inside a function body can't be read from any definition. The hygiene check lists sensitive columns that need a row |
| `steward_list_current` (view) | Today's stewards per policy, plus the overrides | Replay of the policy events | The reconcile, the health check, and reviewers |
| `sensitive_access_events` | One row per read of a sensitive column, with the steward flag, the policy in force, and a review note | The daily check | **Output.** The record the alerts, the dashboard, and reviewers use |
| `sensitive_dashboard_views` | Who opened each dashboard over sensitive data, and how it was published | The daily check | **Output.** Names the viewers of shared-permission dashboards, which lineage can't |
| `sdar_load_log`, `sdar_drift`, `sdar_hygiene` | Copy runs, drift between replayed and live state, weekly hygiene findings | The daily and weekly jobs | Quality checks: a quiet day must be told apart from a broken one |

Only the two output tables name readers, and only the security audience can read them.

## How the daily check decides

For each read of a column on the day being checked:

1. **The read.** Column lineage gives the column, the statement, and the entity (notebook, job, dashboard, Genie space, alert). A read served from the SQL warehouse result cache has no lineage of its own, so the check takes the columns of the statement that computed the cached result (`cache_origin_statement_id` in query history) and keeps the cached read's own identity and time. The cache is shared across identities, so the origin's identity is never used.
2. **Sensitive at that moment.** The column carried a sensitive tag value in `tag_versions` at the read's time.
3. **The reader.** Query history's `executed_as`, the identity whose permissions the mask evaluated.
4. **The mask in force.** The column mask policy whose version was current at the read, attached to the table or one of its parents, whose table condition and column condition both match the tags at that moment. A column with a table-level mask has no ABAC mask; the overrides apply instead.
5. **Steward or not.** The reader is a steward if it was in one of that policy's EXCEPT groups at the read's time, by the membership history, or is named directly in EXCEPT.

SDAR reads a policy condition as one or more positive tag predicates joined by `OR`, optionally with `AND NOT` exclusions: the forms the policy editor writes. The weekly hygiene check lists any policy whose condition doesn't fit that form, so a person can confirm which columns it masks.

## Known limits

- **SDAR records reads that name a sensitive column**, the reads that can show a reader its value. A column used only to filter or join isn't in column lineage, so it isn't recorded: `WHERE ssn LIKE '95%'` records the selected columns, not `ssn`. A masked reader's filter runs on masked values, so it reveals nothing. A steward's filter runs on clear values, so a steward's lookup by SSN, a join of two datasets on a sensitive key, or a derived table selected by a sensitive value is not recorded unless the statement also names a sensitive column. Table lineage shows that such a statement read the table, but can't tell it apart from a read of only the table's other columns.
- **A membership change in Entra ID takes several minutes to apply in Databricks, and a few more to reach the masks.** Databricks applies it 5 to 15 minutes after the change in Entra ID, whether or not the member signs in. The masks then keep the old membership for about 4 more minutes, for Entra ID and Databricks groups alike. SDAR judges each read by the membership Databricks applied at that moment. So for a few minutes after a change, SDAR's flag can differ from what the reader received: after an add, a read can be flagged while the reader still saw masked values; after a removal, a read can be unflagged while the reader still saw clear values.
- **Cached dashboard results stay visible after access changes, and a cached view is not a read.** A published dashboard keeps query results for up to 24 hours and shows them without running a query, so column lineage and query history have no read to record. Removing a steward doesn't remove clear results already cached:
  - On a dashboard with individual data permissions, each viewer has their own cache, and a former steward can see clear results cached while they were a steward until they expire or the viewer refreshes the dashboard.
  - On a dashboard with shared data permissions, every viewer sees the publisher's cached results, so clear results cached while the publisher was a steward stay visible to all viewers until someone refreshes the dashboard or a schedule does. Republishing doesn't clear the cache.

  A browser reload shows the cached result; only the dashboard's refresh button or a schedule runs a new query. No setting turns off or purges the dashboard cache. To limit the exposure:
  - Publish dashboards over sensitive columns with individual data permissions. The shared-permission alert lists the ones that aren't.
  - After removing a steward, refresh the shared-permission dashboards they published, or republish them as a non-steward and refresh them.
  - Put a schedule on shared-permission dashboards over sensitive columns, so the shared cache is replaced at a known interval.
  - Treat 24 hours after a removal as the window in which a former steward's cached results can still be seen.

  The same holds for results already shown elsewhere: a notebook keeps its output, and the SQL editor keeps a user's past results for up to 7 days, so a former steward can reopen clear values they saw while a steward. The SQL warehouse result cache is different: it is invalidated when a table changes, and SDAR records reads it serves (see "How the daily check decides").
- **Table-level masks need an override row.** A mask function attached with `ALTER TABLE ... SET MASK` names its exempt groups inside its body, which no definition exposes. Until `steward_group_overrides` has a row for the table and group, steward reads of that column are recorded but not flagged. The weekly hygiene check lists every sensitive column with a table-level mask and no override.
- **Masks with extra conditions.** The steward flag means the reader was exempt from the mask. A mask that also checks something else, such as the row's region, can still hide some rows from a steward.
- **Sensitive data that isn't tagged.** SDAR watches tagged columns. The hygiene check lists masked columns without a sensitive tag; a column with neither a tag nor a mask isn't found.
- **Group renames.** A group renamed in Entra ID can keep its old name in Databricks for a time. The reconcile finds each Entra ID group by its object ID and reports a name mismatch, so the policies' EXCEPT lists can be checked once Databricks shows the new name.
- **Classic compute.** Lineage links a read to query history through the statement ID, which SQL warehouses and serverless compute provide. For a read with no query history row, the check falls back to lineage's `created_by`.
- **Lineage arrives 10 to 20 minutes after a read, in batches.** The daily check runs the next morning, so it has hours of margin.

## How SDAR was tested

SDAR was tested in a disposable serverless Azure Databricks workspace set up like a typical customer's: Entra ID with automatic identity management, test users and service principals in Entra groups, governed tags, ABAC policies, a table-level mask, synthetic data, dashboards, a Genie space, and an alert. Each scenario was performed as a test identity and written to a ledger with its expected outcome, and SDAR's output for the day was scored against the ledger.

**What was tested**

| Area | Cases |
|---|---|
| Read paths | SQL warehouse queries; notebooks (SQL and DataFrame); serverless jobs, including a `CREATE TABLE AS SELECT` that copies a sensitive column; reads through a view; dashboards with individual and with shared data permissions; a scheduled dashboard refresh; Genie, including a second identity served the first one's cached result; an alert evaluation; reads served from the SQL warehouse result cache |
| Expressions | Selected columns, `SELECT *`, hashes, concatenations, and aggregates of sensitive columns; a column used only in a filter or a join (not recorded, see Known limits) |
| Who is a steward | A member of a steward group; a member of a group nested in it; a user and a service principal named directly in EXCEPT; a steward for one catalog reading another; a policy whose table condition skips a table; a key-only tag condition with an `AND NOT` exclusion; a column with a table-level mask |
| Changes during the day | Entra ID adds and removals for a user and a service principal; a nested group; three members added in one request; a removal with no later sign-in; Databricks-group changes through the account SCIM API; a group added to and removed from a policy's EXCEPT list; a policy created and deleted; a tag removed and restored; a second sensitive tag value |
| Operations | The first run with a year of history; the reconcile; drift after a policy deletion; the weekly hygiene checks; rechecking a day from its events |

**Results.** In the final round, across 124 planned reads of sensitive columns, SDAR recorded every one, named the expected identity for each, and flagged stewards as the design specifies. Its steward flag also matched what the reader actually received, except in the few minutes after a membership change, before the masks caught up, and for a column with a table-level mask before its override row existed (see Known limits). It named every viewer of the dashboards over sensitive data, with the publishing mode. Reads of untagged columns and the negative controls produced no rows. Dashboard views served from the dashboard cache produced no read.

**Not tested:** classic compute, guest users from another Entra ID tenant, BI tools that connect through JDBC or ODBC, groups with thousands of members, policies on views that still evaluate the view owner, RBAC role switching, and group renames beyond the first 45 minutes.

## Deploying into an existing workspace

Deployment needs only the Databricks CLI (1.20 or later) and the bundle in `solution/`. No Terraform.

### One-time prerequisites

| Prerequisite | How | Why the bundle can't do it |
|---|---|---|
| Two service principals: one runs every SDAR job and alert, one runs the membership reconcile | Account console, or Entra ID plus automatic identity management. Give the reconcile principal the account admin role | Bundles have no service principal or role resource |
| The `servicePrincipal.user` role on both principals for the person who deploys | Account console, the service principal, then Permissions | A job can run as a service principal only if its deployer holds this role |
| Workspace access and Databricks SQL access entitlements for both principals | Workspace settings, Identity and access | Bundles have no entitlement resource |
| Entra ID only: the Microsoft Graph application permission `GroupMember.Read.All` on the reconcile principal's app registration, with admin consent, and a client secret on the same registration | Entra admin center, App registrations, the reconcile principal, API permissions, then Certificates & secrets | Under automatic identity management, no Databricks API lists the members of an Entra ID group, so the reconcile reads them from Graph |
| A secret scope for the reconcile's credentials, readable only by the reconcile principal | `databricks secrets create-scope sdar`, `put-acl sdar <reconcile-app-id> READ`, then `put-secret sdar` for `group-reader-client-id` (the reconcile principal's application ID), `group-reader-client-secret` (its Databricks OAuth secret), and, for Entra ID, `graph-tenant-id` and `graph-client-secret` | Top-level bundle permissions apply to every resource, which would let the job principal read the secrets |
| The `access` and `query` system schemas | On by default in most accounts. Otherwise `databricks system-schemas enable` as a metastore admin | Metastore-level setting |

**Azure: keeping the reconcile's secrets in Azure Key Vault.** If your organization keeps secrets in Key Vault, an Azure Key Vault-backed secret scope works with no code change. To read the vault without a scope, create an Access Connector for Azure Databricks, give its managed identity read access to the vault's secrets, create a Unity Catalog service credential from the connector, and grant the reconcile principal `ACCESS` on it. The reconcile reads every secret through its `secret()` function, which is then the one place to change: pass `dbutils.credentials.getServiceCredentialsProvider('<credential>')` to the Azure SDK's `SecretClient`.

### Deploy and run

Set the variables in `solution/databricks.yml` (a `targets.<name>.variables` block), then, as a metastore admin:

```bash
cd solution
databricks bundle deploy -t prod
databricks bundle run sdar_admin_setup -t prod      # grants on system, SDAR's catalog, and each governed catalog
databricks bundle run sdar_setup -t prod            # SDAR's tables, owned by the job principal
databricks bundle run sdar_check -t prod --params lookback_days=365   # first copy of a year of changes, plus the baseline
databricks bundle run sdar_reconcile -t prod        # members older than the audit log
databricks bundle run sdar_hygiene -t prod          # checks that need a person
```

To recheck a day, delete that day's rows from `sensitive_access_events` and `sensitive_dashboard_views` and run `sdar_check` with `check_date` set to the day (`yyyy-MM-dd`). The events it replays are already in SDAR's tables.

## License

MIT. See [LICENSE](LICENSE).
