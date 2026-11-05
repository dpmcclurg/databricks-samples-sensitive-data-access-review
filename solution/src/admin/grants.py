# Databricks notebook source
# SDAR admin setup. Runs once as the deploying admin (a metastore admin), because these grants
# are on objects SDAR doesn't own: the system catalog, SDAR's catalog, and each governed catalog.
# Grants only add. Nothing is revoked, so rerunning is safe.

# COMMAND ----------

for name in ("sdar_catalog", "security_sp", "group_reader_sp", "governed_catalogs"):
    dbutils.widgets.text(name, "")
sdar_catalog = dbutils.widgets.get("sdar_catalog")
security_sp = dbutils.widgets.get("security_sp")
group_reader_sp = dbutils.widgets.get("group_reader_sp")
governed = [c.strip() for c in dbutils.widgets.get("governed_catalogs").split(",") if c.strip()]
assert sdar_catalog and security_sp and group_reader_sp and governed, "all parameters are required"

grants = [
    # Read access to the audit log and lineage tables (system.access) and to query history (system.query).
    f"GRANT USE CATALOG ON CATALOG system TO `{security_sp}`",
    f"GRANT USE SCHEMA, SELECT ON SCHEMA system.access TO `{security_sp}`",
    f"GRANT USE SCHEMA, SELECT ON SCHEMA system.query TO `{security_sp}`",
    # SDAR's catalog. The schema and its grants come from the bundle.
    f"GRANT USE CATALOG ON CATALOG `{sdar_catalog}` TO `{security_sp}`",
    f"GRANT USE CATALOG ON CATALOG `{sdar_catalog}` TO `{group_reader_sp}`",
]
for catalog in governed:
    # BROWSE: information_schema shows only objects the caller can access, so the inventory needs it.
    # READ METADATA: shows ABAC policy definitions, including TO and EXCEPT lists. No data access.
    grants.append(f"GRANT BROWSE ON CATALOG `{catalog}` TO `{security_sp}`")
    grants.append(f"GRANT READ METADATA ON CATALOG `{catalog}` TO `{security_sp}`")

for g in grants:
    spark.sql(g)
    print(g)
