"""
Main migration entry point for New Relic NRQL alert conditions to Dynatrace
Davis anomaly detectors.

High-level flow:
1. Load configuration and initialize logging/output files.
2. Read the requested policy/condition rows from the spreadsheet.
3. Fetch New Relic policies and NRQL conditions.
4. Convert each matched condition into one or more Dynatrace payloads.
5. Send the payloads to Dynatrace and record the result in CSV/log output.
"""

import os
import json
import time
import base64
import sys
import csv
from collections import Counter
from zipfile import ZipFile
import xml.etree.ElementTree as ET
import requests
from dotenv import load_dotenv
from mapper import AlertMapper

load_dotenv()  # loads variables from a .env file if present

# ---------- NEW RELIC CONFIG ----------
NR_API_KEY    = os.environ["NR_API_KEY"]       # User API key (NRAK-...)
NR_ACCOUNT_ID = os.environ["NR_ACCOUNT_ID"]    # New Relic account ID
NR_BASE_URL   = "https://api.newrelic.com/v2"
NERDGRAPH_URL = "https://api.newrelic.com/graphql"

# ---------- DYNATRACE CONFIG ----------
DT_BASE_URL  = os.environ["DT_BASE_URL"].rstrip("/")   # e.g. https://xxx.live.dynatrace.com
DT_API_TOKEN = os.environ.get("DT_API_TOKEN", "")
DT_OAUTH_ACCESS_TOKEN = os.environ.get("DT_OAUTH_ACCESS_TOKEN", "").strip()
DT_OAUTH_TOKEN_URL = os.environ.get("DT_OAUTH_TOKEN_URL", "https://sso.dynatrace.com/sso/oauth2/token").strip()
DT_OAUTH_CLIENT_ID = (
    os.environ.get("DT_CLIENT_ID")
    or os.environ.get("DT_OAUTH_CLIENT_ID", "")
).strip()
DT_OAUTH_CLIENT_SECRET = (
    os.environ.get("DT_CLIENT_SECRET")
    or os.environ.get("DT_OAUTH_CLIENT_SECRET", "")
).strip()
DT_ACCOUNT_URN = os.environ.get("DT_ACCOUNT_URN", "").strip()
DT_OAUTH_SCOPE = os.environ.get("DT_OAUTH_SCOPE", "").strip()
DT_SETTINGS_URL = f"{DT_BASE_URL}/api/v2/settings/objects"
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output")
CONDITION_XLSX_PATH = os.environ.get(
    "CONDITION_XLSX_PATH",
    "prod_alert_policies_conditions-2025-02-17.xlsx",
)
CONDITION_EMAIL_COLUMN = os.environ.get("CONDITION_EMAIL_COLUMN", "email")
SUPPORT_GROUP_COLUMN = os.environ.get("SUPPORT_GROUP_COLUMN", "Support Group")

# ---------- FILTER ----------
# Only look inside this policy. Set to None to search all policies.
TARGET_POLICY_NAME    = "SRE-API-Limit"
# Only migrate this specific condition. Set to None to migrate all.
TARGET_CONDITION_NAME = "SRE-MOXE-API-Limit-productpricing-HigherLimit"

# ---------- HEADERS ----------
nr_headers = {
    "X-Api-Key": NR_API_KEY,
    "Content-Type": "application/json"
}
# NerdGraph uses API-Key header
nerdgraph_headers = {
    "API-Key": NR_API_KEY,
    "Content-Type": "application/json"
}
DEFAULT_DT_SCHEMA_IDS = {
    "alerting_profile": os.environ.get("DT_ALERTING_PROFILE_SCHEMA_ID", "builtin:alerting.profile"),
    "metric_event": os.environ.get("DT_METRIC_EVENT_SCHEMA_ID", "builtin:davis.anomaly-detectors"),
    "notification": os.environ.get("DT_NOTIFICATION_SCHEMA_ID", "builtin:alerting.notification"),
}

DEFAULT_DT_SCHEMA_VERSIONS = {
    "alerting_profile": os.environ.get("DT_ALERTING_PROFILE_SCHEMA_VERSION", "0.0.27"),
    "metric_event": os.environ.get("DT_METRIC_EVENT_SCHEMA_VERSION", "1.0.13"),
    "notification": os.environ.get("DT_NOTIFICATION_SCHEMA_VERSION"),
}


# ---------- DYNATRACE API HELPERS ----------

_dt_oauth_cache: dict = {}


class TeeStream:
    """Write console output to both the terminal and a file."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)
            stream.flush()
        return len(data)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def setup_console_log() -> str:
    """Mirror stdout/stderr to a timestamped log file in the project output directory."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(OUTPUT_DIR, f"migrate-{timestamp}.log")
    log_file = open(log_path, "a", encoding="utf-8")

    sys.stdout = TeeStream(sys.stdout, log_file)
    sys.stderr = TeeStream(sys.stderr, log_file)
    print(f"Logging console output to: {log_path}")
    return log_path


LOG_FILE_PATH = setup_console_log()
CSV_REPORT_PATH = os.path.join(OUTPUT_DIR, "migration_results.csv")
print(f"Writing CSV results to: {CSV_REPORT_PATH}")


def append_csv_result(row: dict) -> None:
    """Append one migration result row to the CSV report."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    fieldnames = [
        "policy_name",
        "condition_name",
        "nr_condition_id",
        "nr_term_count",
        "nr_term_priority",
        "nr_operator",
        "nr_operator_rule",
        "nr_threshold_occurrences",
        "nr_occurrence_rule",
        "nr_threshold_value",
        "dt_alert_condition",
        "dt_threshold_value",
        "violating_samples",
        "dealerting_samples",
        "sliding_window",
        "dt_title",
        "query",
        "converted_query_dql",
        "error_payload",
    ]
    expected_header = ",".join(fieldnames)
    should_write_header = True
    file_mode = "a"

    if os.path.exists(CSV_REPORT_PATH):
        try:
            with open(CSV_REPORT_PATH, "r", encoding="utf-8", newline="") as existing_file:
                first_line = existing_file.readline().strip()
            should_write_header = first_line != expected_header
            if should_write_header:
                file_mode = "w"
        except OSError:
            should_write_header = True
            file_mode = "w"

    with open(CSV_REPORT_PATH, file_mode, newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        if should_write_header:
            writer.writeheader()
        writer.writerow({key: row.get(key, "") for key in fieldnames})


def dedupe_conditions_by_id(conditions: list[dict]) -> list[dict]:
    """Keep the first occurrence of each NR condition id."""
    unique_conditions: list[dict] = []
    seen_condition_ids: set[str] = set()

    for condition in conditions:
        condition_id = str(condition.get("id", "")).strip()
        if condition_id and condition_id in seen_condition_ids:
            print(
                f"  Skipping duplicate condition returned by New Relic: "
                f"{condition.get('name', '')} (id={condition_id})"
            )
            continue
        if condition_id:
            seen_condition_ids.add(condition_id)
        unique_conditions.append(condition)

    return unique_conditions


def load_condition_requests_from_xlsx(
    xlsx_path: str,
    policy_column_name: str = "policyName",
    condition_column_name: str = "ConditionName",
    email_column_name: str = CONDITION_EMAIL_COLUMN,
    support_group_column_name: str = SUPPORT_GROUP_COLUMN,
) -> list[dict]:
    """Read requested policy/condition rows and optional owner email from an xlsx file."""
    namespace = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

    def column_letters(cell_ref: str) -> str:
        return "".join(ch for ch in cell_ref if ch.isalpha())

    def cell_text(cell: ET.Element, shared_strings: list[str]) -> str:
        cell_type = cell.get("t")
        value = cell.find("main:v", namespace)
        if value is None or value.text is None:
            inline = cell.find("main:is/main:t", namespace)
            return inline.text.strip() if inline is not None and inline.text else ""
            # unreachable, kept for clarity
        raw = value.text.strip()
        if cell_type == "s":
            return shared_strings[int(raw)]
        return raw

    with ZipFile(xlsx_path) as workbook:
        shared_strings: list[str] = []
        if "xl/sharedStrings.xml" in workbook.namelist():
            root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
            for item in root.findall("main:si", namespace):
                text_parts = [node.text or "" for node in item.findall(".//main:t", namespace)]
                shared_strings.append("".join(text_parts))

        sheet_root = ET.fromstring(workbook.read("xl/worksheets/sheet1.xml"))
        rows = sheet_root.findall(".//main:sheetData/main:row", namespace)
        if not rows:
            return []

        header_map: dict[str, str] = {}
        for cell in rows[0].findall("main:c", namespace):
            header_map[column_letters(cell.get("r", ""))] = cell_text(cell, shared_strings)

        policy_column = None
        condition_column = None
        email_column = None
        for col, header in header_map.items():
            normalized = header.strip().lower()
            if normalized == policy_column_name.lower():
                policy_column = col
            if normalized == condition_column_name.lower():
                condition_column = col
            if normalized == email_column_name.lower():
                email_column = col
            if normalized == support_group_column_name.lower():
                support_group_column = col

        if not policy_column or not condition_column:
            raise RuntimeError(
                f"Columns '{policy_column_name}' and/or '{condition_column_name}' not found in {xlsx_path}. "
                f"Available columns: {list(header_map.values())}"
            )
        if not email_column:
            print(
                f"Warning: Email column '{email_column_name}' not found in {xlsx_path}. "
                "Dynatrace event property 'email' will be omitted."
            )
        if not support_group_column:
            print(
                f"Warning: Support Group column '{support_group_column_name}' not found in {xlsx_path}. "
                "Dynatrace event property 'support_group' will be omitted."
            )

        condition_requests: list[dict] = []
        for row in rows[1:]:
            policy_name = ""
            condition_name = ""
            email = ""
            for cell in row.findall("main:c", namespace):
                column_ref = column_letters(cell.get("r", ""))
                if column_ref == policy_column:
                    policy_name = cell_text(cell, shared_strings).strip()
                elif column_ref == condition_column:
                    condition_name = cell_text(cell, shared_strings).strip()
                elif email_column and column_ref == email_column:
                    email = cell_text(cell, shared_strings).strip()
                elif support_group_column and column_ref == support_group_column:
                    support_group = cell_text(cell, shared_strings).strip()
            if condition_name:
                condition_requests.append({
                    "policy_name": policy_name,
                    "condition_name": condition_name,
                    "email": email,
                    "support_group": support_group,
                })

        return condition_requests


def _decode_jwt_payload(token: str) -> dict:
    """Best-effort JWT payload decode without signature verification."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def dt_env_access_token_valid() -> bool:
    """Return True when the env bearer token exists and is not expired."""
    if not DT_OAUTH_ACCESS_TOKEN:
        return False

    payload = _decode_jwt_payload(DT_OAUTH_ACCESS_TOKEN)
    exp = payload.get("exp")
    if not exp:
        return True

    # Refresh a little before actual expiry.
    return time.time() < (float(exp) - 60)


def dt_invalidate_tokens() -> None:
    """Clear any cached/generated tokens for a retry."""
    _dt_oauth_cache.clear()


def dt_get_headers() -> dict:
    """Build Dynatrace headers using OAuth when configured, else fall back to API token."""
    if dt_env_access_token_valid():
        print("  [DT] Auth mode: Bearer token from env")
        return {
            "Authorization": f"Bearer {DT_OAUTH_ACCESS_TOKEN}",
            "Content-Type": "application/json",
        }
    if DT_OAUTH_ACCESS_TOKEN:
        print("  [DT] Env bearer token expired or invalid, falling back to OAuth token generation.")

    if (
        DT_OAUTH_TOKEN_URL
        and DT_OAUTH_CLIENT_ID
        and DT_OAUTH_CLIENT_SECRET
        and DT_ACCOUNT_URN
    ):
        print("  [DT] Auth mode: OAuth")
        access_token = dt_get_oauth_access_token()
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

    if DT_API_TOKEN:
        print("  [DT] Auth mode: Api-Token")
        return {
            "Authorization": f"Api-Token {DT_API_TOKEN}",
            "Content-Type": "application/json",
        }

    raise RuntimeError(
        "Dynatrace authentication is not configured. "
        "Set either DT_API_TOKEN or DT_CLIENT_ID/DT_CLIENT_SECRET/DT_ACCOUNT_URN."
    )


def dt_get_oauth_access_token() -> str:
    """Fetch and cache an OAuth access token using client credentials."""
    if not DT_OAUTH_TOKEN_URL:
        raise RuntimeError(
            "DT_OAUTH_TOKEN_URL is empty. Set it to the Dynatrace SSO token endpoint "
            "or remove the OAuth variables to use DT_API_TOKEN."
        )

    cached_token = _dt_oauth_cache.get("access_token")
    if cached_token:
        return cached_token

    data = {
        "grant_type": "client_credentials",
        "client_id": DT_OAUTH_CLIENT_ID,
        "client_secret": DT_OAUTH_CLIENT_SECRET,
        "resource": DT_ACCOUNT_URN,
    }
    if DT_OAUTH_SCOPE:
        data["scope"] = DT_OAUTH_SCOPE

    response = requests.post(
        DT_OAUTH_TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    print(f"  [DT] OAuth token status: {response.status_code}")
    print(f"  [DT] OAuth token response: {response.text[:1000]}")
    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to fetch Dynatrace OAuth token: {response.status_code} {response.text[:300]}"
        )

    token = response.json().get("access_token")
    if not token:
        raise RuntimeError("Dynatrace OAuth token response did not include access_token.")

    print("  [DT] OAuth token acquired successfully.")
    _dt_oauth_cache["access_token"] = token
    return token

def dt_get_schema_version(schema_id: str) -> str | None:
    """Fetch the latest schema version from Dynatrace for a settings schema id."""
    url = f"{DT_BASE_URL}/api/v2/settings/schemas/{schema_id}"
    response = requests.get(url, headers=dt_get_headers())
    if response.status_code == 200:
        version = response.json().get("latestSchemaVersion")
        print(f"  [DT] Schema {schema_id} latest version: {version}")
        return version
    else:
        print(f"  [DT] Could not fetch schema version for {schema_id}: {response.text[:200]}")
        return None


def dt_create_settings_object(payload: dict) -> dict:
    """
    POST a single settings object to Dynatrace Settings API v2.

    The Settings API expects a list payload, so this helper always wraps the
    provided object in a one-element list and returns a structured status
    dictionary for CSV/log reporting.
    """
    if DRY_RUN:
        print("  [DT] DRY_RUN=true — skipping actual API call.")
        return {
            "success": True,
            "object_id": "dry-run-id",
            "status_code": None,
            "error_text": "",
            "payload": payload,
        }

    response = requests.post(
        DT_SETTINGS_URL,
        headers=dt_get_headers(),
        json=[payload],   # Settings API expects a list
    )

    if response.status_code == 401 and (
        DT_OAUTH_ACCESS_TOKEN or (
            DT_OAUTH_TOKEN_URL
            and DT_OAUTH_CLIENT_ID
            and DT_OAUTH_CLIENT_SECRET
            and DT_ACCOUNT_URN
        )
    ):
        print("  [DT] Received 401. Clearing cached token state and retrying once with a fresh OAuth token.")
        dt_invalidate_tokens()
        response = requests.post(
            DT_SETTINGS_URL,
            headers=dt_get_headers(),
            json=[payload],
        )

    if response.status_code in (200, 207):
        result = response.json()
        object_id = result[0].get("objectId") if result else None
        code      = result[0].get("code") if result else None
        return {
            "success": True,
            "object_id": object_id,
            "status_code": response.status_code,
            "error_text": "",
            "response_code": code,
            "payload": payload,
        }
    else:
        print(f"  [DT] Error {response.status_code}: {response.text}")
        print(f"  [DT] Error Payload:\n{json.dumps(payload, indent=4)}")
        return {
            "success": False,
            "object_id": None,
            "status_code": response.status_code,
            "error_text": response.text,
            "payload": payload,
        }


def dt_create_alerting_profile(policy: dict, mapper: AlertMapper) -> str | None:
    """Create a Dynatrace alerting profile from a New Relic policy definition."""
    payload = mapper.map_policy_to_alerting_profile(policy)

    print(f"\n  [DT] Creating alerting profile for policy: {policy['name']}")
    return dt_create_settings_object(payload)


def fetch_nrql_conditions_nerdgraph(policy_id: str) -> list:
    """
    Fetch NRQL alert conditions via NerdGraph (GraphQL).

    This is used instead of the legacy REST conditions endpoint because newer
    alert conditions created in the New Relic UI are exposed reliably through
    NerdGraph.
    """
    query = """
    {
      actor {
        account(id: %s) {
          alerts {
            nrqlConditionsSearch(searchCriteria: {policyId: "%s"}) {
              nrqlConditions {
                id
                name
                enabled
                nrql {
                  query
                }
                runbookUrl
                terms {
                  threshold
                  thresholdDuration
                  thresholdOccurrences
                  operator
                  priority
                }
                signal {
                  aggregationWindow
                  evaluationDelay
                }
              }
            }
          }
        }
      }
    }
    """ % (NR_ACCOUNT_ID, policy_id)

    response = requests.post(
        NERDGRAPH_URL,
        headers=nerdgraph_headers,
        json={"query": query},
    )

    print(f"  [NerdGraph] status: {response.status_code}")
    if response.status_code != 200:
        print(f"  [NerdGraph] Error: {response.text[:300]}")
        return []

    data = response.json()
    errors = data.get("errors")
    if errors:
        print(f"  [NerdGraph] GraphQL errors: {errors}")
        return []

    conditions = (
        data.get("data", {})
            .get("actor", {})
            .get("account", {})
            .get("alerts", {})
            .get("nrqlConditionsSearch", {})
            .get("nrqlConditions", [])
    )
    print(f"  [NerdGraph] {len(conditions)} NRQL condition(s) found")
    return conditions


DT_SCHEMA_IDS = DEFAULT_DT_SCHEMA_IDS.copy()
DT_SCHEMA_VERSIONS = DEFAULT_DT_SCHEMA_VERSIONS.copy()
MAPPER = AlertMapper(
    schema_ids=DT_SCHEMA_IDS,
    schema_versions=DT_SCHEMA_VERSIONS,
)
REQUESTED_CONDITION_REQUESTS = load_condition_requests_from_xlsx(CONDITION_XLSX_PATH)
print(
    f"Loaded {len(REQUESTED_CONDITION_REQUESTS)} requested policy/condition row(s) from "
    f"{CONDITION_XLSX_PATH}"
)

if (
    DT_SCHEMA_IDS.get("metric_event") == "builtin:davis.anomaly-detectors"
    and not os.environ.get("DT_DAVIS_ACTOR_ID", "").strip()
):
    print("Error: DT_DAVIS_ACTOR_ID is required for builtin:davis.anomaly-detectors.")
    print("Set DT_DAVIS_ACTOR_ID in .env to the actor UUID from an existing Davis anomaly detector.")
    exit()

# ---------- Fetch ALL Alert Policies (handles pagination) ----------
policies = []
page = 1
while True:
    policies_url = f"{NR_BASE_URL}/alerts_policies.json?page={page}"
    response = requests.get(policies_url, headers=nr_headers)

    if response.status_code != 200:
        print(f"Error fetching alert policies (page {page}): {response.status_code}")
        print(response.text)
        exit()

    page_policies = response.json().get("policies", [])
    if not page_policies:
        break  # no more pages

    policies.extend(page_policies)
    print(f"  Fetched page {page} ({len(page_policies)} policies, {len(policies)} total so far...)")
    page += 1

print(f"\nTotal policies fetched: {len(policies)}")
remaining_condition_requests = [
    request for request in REQUESTED_CONDITION_REQUESTS
    if request.get("condition_name", "").strip()
]
processed_condition_ids: set[str] = set()
matched_condition_count = 0
created_payload_count = 0
operator_rule_counts: Counter[str] = Counter()
occurrence_rule_counts: Counter[str] = Counter()
operator_name_counts: Counter[str] = Counter()

for policy in policies:
    if not remaining_condition_requests:
        break

    print(f"Policy Name: {policy['name']}")
    print(f"Policy ID: {policy['id']}")
    print(f"Incident Preference: {policy['incident_preference']}")
    print("-" * 40)

    # ---------- Fetch NRQL Conditions via NerdGraph ----------
    conditions = dedupe_conditions_by_id(fetch_nrql_conditions_nerdgraph(policy["id"]))
    requested_names_for_policy = {
        request["condition_name"].strip()
        for request in remaining_condition_requests
        if request.get("policy_name", "").strip() == policy["name"].strip()
        and request.get("condition_name", "").strip()
    }
    request_by_condition_name = {
        request["condition_name"].strip(): request
        for request in remaining_condition_requests
        if request.get("policy_name", "").strip() == policy["name"].strip()
        and request.get("condition_name", "").strip()
    }
    if not requested_names_for_policy:
        continue
    matched_conds = [
        c for c in conditions
        if c.get("name", "").strip() in requested_names_for_policy
    ]
    if not matched_conds:
        continue

    unique_matched_conds = []
    for matched_cond in matched_conds:
        condition_id = str(matched_cond.get("id", "")).strip()
        if condition_id and condition_id in processed_condition_ids:
            print(
                f"  Skipping already processed condition: "
                f"{matched_cond.get('name', '')} (id={condition_id})"
            )
            continue
        if condition_id:
            processed_condition_ids.add(condition_id)
        unique_matched_conds.append(matched_cond)

    matched_conds = unique_matched_conds
    if not matched_conds:
        continue

    print(f"  Matched {len(matched_conds)} requested condition(s).")
    for matched_cond in matched_conds:
        matched_name = matched_cond["name"].strip()
        remaining_condition_requests = [
            request for request in remaining_condition_requests
            if not (
                request.get("policy_name", "").strip() == policy["name"].strip()
                and request.get("condition_name", "").strip() == matched_name
            )
        ]

    # ---------- Step 1: Map & Push each matched condition ----------

    for cond in matched_conds:
        matched_condition_count += 1
        for term in cond.get("terms", []):
            nr_operator = str(term.get("operator", "UNKNOWN")).upper()
            threshold_occurrences = str(term.get("thresholdOccurrences", "ALL")).upper()
            operator_name_counts[nr_operator] += 1
            operator_rule_counts[{
                "ABOVE": "6.1",
                "ABOVE_OR_EQUALS": "6.2",
                "BELOW": "6.3",
                "BELOW_OR_EQUALS": "6.4",
                "EQUALS": "6.5",
                "NOT_EQUALS": "6.6",
            }.get(nr_operator, "UNKNOWN")] += 1
            occurrence_rule_counts["6.7" if threshold_occurrences == "ALL" else "6.8"] += 1
        nrql_query = cond.get("nrql", {}).get("query", "")
        converted_dql = ""

        print(f"\n  Condition Name : {cond['name']}")
        print(f"  Enabled        : {cond['enabled']}")
        print(f"  NRQL Query     : {nrql_query}")
        print(f"  Full Condition : {cond}")

        # Convert NRQL → DQL and print
        if nrql_query:
            dql_result = MAPPER.converter.convert(nrql_query)
            if isinstance(dql_result, dict):
                converted_dql = dql_result.get("dql", "")
                confidence = "n/a"
                warnings = dql_result.get("warnings", [])
                manual_review = dql_result.get("manual_review_needed", [])
                if dql_result.get("needs_manual_review"):
                    manual_review = manual_review or ["Manual review needed"]
            else:
                converted_dql = dql_result.converted_dql
                confidence = dql_result.confidence
                warnings = dql_result.warnings
                manual_review = dql_result.manual_review_needed

            print(f"  DQL Query      : {converted_dql}")
            print(f"  Confidence     : {confidence}")
            if warnings:
                for w in warnings:
                    print(f"  Warning        : {w}")
            if manual_review:
                for r in manual_review:
                    print(f"  Manual Review  : {r}")

        # Build DT payloads (one per severity term)
        condition_request = request_by_condition_name.get(cond["name"].strip(), {})
        print(f"  Condition request from spreadsheet: {condition_request}")
        event_email = condition_request.get("email", "")
        event_supportGroup = condition_request.get("support_group", "")
        #event_runbookUrl = condition_request.get("runbook_url", "")
        dt_payloads = MAPPER.map_condition_to_custom_alerts(
            condition=cond,
            policy_name=policy["name"],
            email=event_email,
            support_group=event_supportGroup,
            #runbook_url=event_runbookUrl,
        )

        if not dt_payloads:
            print("  [DT] No payloads generated (condition may need USF review).")
            continue

        # ---------- Step 2: Push each payload to Dynatrace ----------
        for i, payload in enumerate(dt_payloads, 1):
            created_payload_count += 1
            severity = (
                payload["value"].get("summary")
                or payload["value"].get("title")
                or f"term {i}"
            )
            payload_meta = payload.get("_meta", {})
            analyzer_inputs = payload.get("value", {}).get("analyzer", {}).get("input", [])
            threshold_value = next(
                (item.get("value", "") for item in analyzer_inputs if item.get("key") == "threshold"),
                "",
            )
            alert_condition_value = next(
                (item.get("value", "") for item in analyzer_inputs if item.get("key") == "alertCondition"),
                "",
            )
            term_priority = "UNKNOWN"
            title_text = payload["value"].get("title", "")
            if "[CRITICAL]" in title_text:
                term_priority = "CRITICAL"
            elif "[WARNING]" in title_text:
                term_priority = "WARNING"
            print(f"\n  [DT] Pushing alert [{i}/{len(dt_payloads)}]: {severity}")
            result = dt_create_settings_object(payload)
            append_csv_result({
                "policy_name": policy["name"],
                "condition_name": cond["name"],
                "nr_condition_id": cond.get("id", ""),
                "nr_term_count": len(cond.get("terms", [])),
                "nr_term_priority": payload_meta.get("nr_term_priority", term_priority),
                "nr_operator": payload_meta.get("nr_operator", ""),
                "nr_operator_rule": payload_meta.get("rule_operator_category", ""),
                "nr_threshold_occurrences": payload_meta.get("nr_threshold_occurrences", ""),
                "nr_occurrence_rule": payload_meta.get("rule_occurrence_category", ""),
                "nr_threshold_value": payload_meta.get("nr_threshold", ""),
                "dt_alert_condition": payload_meta.get("dt_alert_condition", alert_condition_value),
                "dt_threshold_value": payload_meta.get("dt_threshold", threshold_value),
                "violating_samples": payload_meta.get("violating_samples", ""),
                "dealerting_samples": payload_meta.get("dealerting_samples", ""),
                "sliding_window": payload_meta.get("sliding_window", ""),
                "dt_title": title_text,
                "query": nrql_query,
                "converted_query_dql": converted_dql,
                "error_payload": "" if result.get("success") else json.dumps({
                    "status_code": result.get("status_code"),
                    "error_text": result.get("error_text"),
                    "payload": result.get("payload"),
                }),
            })

    print("=" * 50)

print(f"Matched New Relic conditions: {matched_condition_count}")
print(f"Created Dynatrace payloads: {created_payload_count}")
# if operator_rule_counts:
#     print("New Relic threshold operator counts by rule:")
#     for rule_id in ("6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "UNKNOWN"):
#         if operator_rule_counts.get(rule_id):
#             print(f"  Rule {rule_id}: {operator_rule_counts[rule_id]}")
# if operator_name_counts:
#     print("New Relic operators encountered:")
#     for operator_name, count in sorted(operator_name_counts.items()):
#         print(f"  {operator_name}: {count}")
# if occurrence_rule_counts:
#     print("New Relic threshold occurrence counts by rule:")
#     for rule_id in ("6.7", "6.8"):
#         if occurrence_rule_counts.get(rule_id):
#             print(f"  Rule {rule_id}: {occurrence_rule_counts[rule_id]}")
# if remaining_condition_requests:
#     print(f"Unmatched spreadsheet rows: {len(remaining_condition_requests)}")
#     for request in remaining_condition_requests[:20]:
#         print(
#             "  Unmatched: "
#             f"policy='{request.get('policy_name', '')}', "
#             f"condition='{request.get('condition_name', '')}'"
#         )
