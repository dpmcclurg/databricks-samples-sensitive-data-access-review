# Databricks notebook source
# Membership reconcile. Run by hand as the group-reader service principal: at setup after the first
# membership copy, then quarterly, or when the health check reports a steward group with no members.
#
# The daily copy replays membership changes from the audit log, which can't show anyone who joined a steward
# group before the audit log's window. This run compares each steward group's current members with SDAR's
# history and adds a reconcile row for each member SDAR is missing. A member with no recorded change at all
# joined before the window, so that row is back-dated. Members SDAR has but the directory doesn't are listed
# for review. Nothing is removed.
#
# Where the members come from. Each steward group is found in the Databricks account by name, the name the
# policies use. A group from Entra ID carries the Entra object ID as its externalId:
#   Entra ID groups (automatic identity management): Microsoft Graph, looked up by that object ID, so a group
#     renamed in Entra is still found. Under AIM, no Databricks API lists the members of an Entra group. Graph
#     transitive membership includes nested groups, and returns users by userPrincipalName and service
#     principals by appId, the forms query history records. A group whose Entra name differs from its
#     Databricks name is reported under "renamed": check the policies' EXCEPT lists once Databricks shows
#     the new name.
#   Databricks-native groups (no externalId), and accounts without the Graph secret: the account SCIM API.
# Secrets in the scope: group-reader-client-id (the reconcile principal's application ID), group-reader-client-secret
# (its Databricks OAuth secret, for the account groups API), and, for Entra ID groups, graph-tenant-id and
# graph-client-secret (the same app registration's Entra secret).

# COMMAND ----------

import json
import re
import uuid
from datetime import datetime, timezone

import requests
from pyspark.sql import functions as F

for name in ("sdar_catalog", "sdar_schema", "account_id", "account_host", "secret_scope"):
    dbutils.widgets.text(name, "")
sdar = f"{dbutils.widgets.get('sdar_catalog')}.{dbutils.widgets.get('sdar_schema')}"
scope = dbutils.widgets.get("secret_scope")
spark.conf.set("spark.sql.session.timeZone", "UTC")


def secret(key):
    try:
        return dbutils.secrets.get(scope, key)
    except Exception:
        return None


CLIENT_ID = secret("group-reader-client-id")

# COMMAND ----------

GRAPH = "https://graph.microsoft.com/v1.0"
_graph_token = None


def graph_token():
    global _graph_token
    if _graph_token is None:
        r = requests.post(f"https://login.microsoftonline.com/{secret('graph-tenant-id')}/oauth2/v2.0/token",
                          data={"grant_type": "client_credentials", "client_id": CLIENT_ID,
                                "client_secret": secret("graph-client-secret"),
                                "scope": "https://graph.microsoft.com/.default"}, timeout=60)
        r.raise_for_status()
        _graph_token = r.json()["access_token"]
    return {"Authorization": f"Bearer {_graph_token}", "ConsistencyLevel": "eventual"}


def graph_get(url, params=None):
    """GET a Microsoft Graph collection with app-only credentials, following @odata.nextLink."""
    out, next_url = [], url
    while next_url:
        r = requests.get(next_url, headers=graph_token(), params=params, timeout=60)
        r.raise_for_status()
        body = r.json()
        out += body.get("value", [])
        next_url, params = body.get("@odata.nextLink"), None   # nextLink already carries the query
    return out


def graph_members(object_id):
    """(Entra display name, transitive members) of the Entra group with this object ID, or None if Graph has
    no such group. Each member type is listed with its own cast: an uncast listing can omit service principals."""
    r = requests.get(f"{GRAPH}/groups/{object_id}", headers=graph_token(), params={"$select": "id,displayName"},
                     timeout=60)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    users = graph_get(f"{GRAPH}/groups/{object_id}/transitiveMembers/microsoft.graph.user",
                      {"$select": "userPrincipalName,mail,userType", "$count": "true", "$top": "999"})
    sps = graph_get(f"{GRAPH}/groups/{object_id}/transitiveMembers/microsoft.graph.servicePrincipal",
                    {"$select": "appId", "$count": "true", "$top": "999"})
    # A guest's Databricks user name is their email, not the #EXT# user principal name.
    people = {(u.get("mail") if u.get("userType") == "Guest" and u.get("mail") else u["userPrincipalName"]).lower()
              for u in users}
    people |= {s["appId"].lower() for s in sps}
    return r.json()["displayName"], people


# COMMAND ----------

_acct = None


def account():
    global _acct
    if _acct is None:
        from databricks.sdk import AccountClient
        _acct = AccountClient(host=dbutils.widgets.get("account_host"), account_id=dbutils.widgets.get("account_id"),
                              client_id=CLIENT_ID, client_secret=secret("group-reader-client-secret"))
    return _acct


def account_group(group_name):
    """The Databricks account group with this display name, including its externalId, or None."""
    groups = list(account().groups.list(filter=f'displayName eq "{group_name}"', attributes="id,displayName,externalId"))
    return groups[0] if groups else None


def scim_members(group):
    """Members of a Databricks account group, from SCIM. Empty for Entra groups under AIM."""
    a, people = account(), set()
    for m in a.groups.get(group.id).members or []:
        if "Groups/" in (m.ref or ""):
            continue   # nested native groups: list them in steward_group_overrides
        if "ServicePrincipals/" in (m.ref or ""):
            people.add(a.service_principals.get(m.value).application_id.lower())
        else:
            people.add(a.users.get(m.value).user_name.lower())
    return people


# COMMAND ----------

# Today's steward groups. Users and service principals named directly in EXCEPT are matched in the check
# without a group, so only groups are reconciled.
APP_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
stewards = sorted({r.steward for r in spark.table(f"{sdar}.steward_list_current").select("steward").collect()
                   if "@" not in r.steward and not APP_ID.match(r.steward)})
if not stewards:
    raise RuntimeError("No steward groups found. Run the check job first so SDAR has the policies.")

current = {(r.group_name, r.member_name) for r in spark.table(f"{sdar}.group_membership_current").collect()}
has_history = {(r.group_name, r.member_name) for r in
               spark.table(f"{sdar}.group_membership_events").select("group_name", "member_name").distinct().collect()}

now = datetime.now(timezone.utc)
BEFORE_AUDIT = datetime(2000, 1, 1, tzinfo=timezone.utc)   # member since before the audit log began
rows, for_review, source_of, not_found, renamed = [], [], {}, [], []
use_graph = bool(secret("graph-client-secret"))
for name in stewards:
    group = account_group(name)
    if group is None:
        not_found.append(name)
        continue
    if group.external_id and use_graph:
        found = graph_members(group.external_id)
        if found is None:
            not_found.append(name)
            continue
        entra_name, people = found
        source_of[name] = "graph"
        if entra_name != name:
            renamed.append((name, entra_name))
    else:
        people, source_of[name] = scim_members(group), "scim"
    for member in sorted(people):
        if (name, member) not in current:
            t = now if (name, member) in has_history else BEFORE_AUDIT
            rows.append((f"reconcile-{uuid.uuid4()}", t, t.date(), name, member, "add", None, "reconcile", now))
    for_review += [(g, m) for (g, m) in current if g == name and m not in people]

schema = ("source_event_id string, event_time timestamp, event_date date, group_name string, "
          "member_name string, action string, membership_type string, source string, loaded_at timestamp")
if rows:
    spark.createDataFrame(rows, schema).write.mode("append").saveAsTable(f"{sdar}.group_membership_events")

summary = {
    "rows_added": len(rows),
    "added": sorted({(r[3], r[4]) for r in rows}),
    "steward_groups": source_of,
    "groups_not_found": not_found,
    "renamed": renamed,                 # (Databricks name, Entra name): check the policies' EXCEPT lists
    "for_review": sorted(for_review),   # in SDAR's membership but not in the directory; not removed
}
print(summary)
dbutils.notebook.exit(json.dumps(summary, default=str))
