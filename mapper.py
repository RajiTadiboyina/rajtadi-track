"""
Maps New Relic alert constructs to Dynatrace equivalents.
Applies all rules from "Alert Condition Migration Rules v1".
"""

import datetime
import os
import logging
from sqlite3 import Date
from nrql_to_dql import NRQLtoDQLConverter
from migration_rules import (
    TITLE_TEMPLATE_CRITICAL,
    TITLE_TEMPLATE_WARNING,
    EVENT_DESCRIPTION_TEMPLATE,
    EVENT_TYPE,
    ALERT_GROUP,
    PRIORITY_MAP,
    OPERATOR_RULES,
)

logger = logging.getLogger(__name__)


class AlertMapper:
    """
    Applies migration rules v1 to convert NR alerts → DT custom alerts.
    """

    def __init__(
        self,
        schema_ids: dict | None = None,
        schema_versions: dict | None = None,
    ):
        """Initialize the mapper with optional schema id/version overrides."""
        self.converter = NRQLtoDQLConverter()
        self.usf_review_items: list[dict] = []   # Rule 6.5 / 6.6 tracking
        self.schema_ids = {
            "alerting_profile": "builtin:alerting.profile",
            "metric_event": "builtin:davis.anomaly-detectors",
            "notification": "builtin:alerting.notification",
        }
        self.schema_versions = {
            "alerting_profile": "0.0.27",
            "metric_event": "1.0.13",
            "notification": None,
        }
        if schema_ids:
            self.schema_ids.update({k: v for k, v in schema_ids.items() if v})
        if schema_versions:
            self.schema_versions.update({k: v for k, v in schema_versions.items() if v})

    # ── Rule 1: Policy → One Custom Alert per Threshold ───────────────────────

    def map_policy_to_alerting_profile(self, policy: dict) -> dict:
        """Convert a NR policy to a DT alerting profile (Rule 1)."""
        return {
            "schemaId": self.schema_ids["alerting_profile"],
            "schemaVersion": self.schema_versions["alerting_profile"],
            "scope": "environment",
            "value": {
                "name": policy["name"],
                "description": (
                    f"Migrated from New Relic policy ID: {policy['id']}"
                ),
                "managementZones": [],
                "eventFilters": [{"type": "ALL"}],
                "metadata": {
                    "nr_policy_id":     policy["id"],
                    "nr_incident_pref": policy.get("incidentPreference", ""),
                },
            },
        }

    def map_condition_to_custom_alerts(
        self,
        condition: dict,
        policy_name: str,
        alerting_profile_id: str | None = None,
        support_group: str = "",
        email: str = "",
    ) -> list[dict]:
        """
        Rule 1: Each NR condition threshold → one DT custom alert per severity term.
        Rule 1: Loss of signal → DO NOT create separate alert.

        Returns a list of DT metric event payloads (one per term/severity).
        Also populates self.usf_review_items for rules 6.5/6.6.
        """
        results = []
        seen_payload_signatures: set[tuple] = set()
        terms   = condition.get("terms", [])
        signal  = condition.get("signal", {})
        nrql    = condition.get("nrql", {}).get("query", "")

        window_duration_s = int(signal.get("aggregationWindow", 60))
        delay_s           = window_duration_s  # Rule 4.2: delay == window duration

        # Convert NRQL → DQL once (shared across terms)
        # New converter returns a ConversionResult dataclass
        _result = self.converter.convert(nrql, window_duration_s, delay_s, condition.get("name", ""))
        if isinstance(_result, dict):
            dql_result = {
                "dql": _result.get("dql", ""),
                "interval": _result.get("interval", self._seconds_to_duration(window_duration_s)),
                "delay": _result.get("delay", self._seconds_to_duration(delay_s)),
                "warnings": _result.get("warnings", []),
                "needs_manual_review": _result.get("needs_manual_review", False),
            }
        else:
            dql_result = {
                "dql":                 _result.converted_dql,
                "interval":            self._seconds_to_duration(window_duration_s),
                "delay":               self._seconds_to_duration(delay_s),
                "warnings":            _result.warnings + _result.manual_review_needed,
                "needs_manual_review": len(_result.manual_review_needed) > 0,
            }
        actor_id = os.environ.get("DT_DAVIS_ACTOR_ID", "").strip()

        for term in terms:
            priority = term.get("priority", "CRITICAL").upper()

            # ── Rule 2/3: Build title ──────────────────────────────────────────
            if priority == "CRITICAL":
                title = TITLE_TEMPLATE_CRITICAL.format(
                    policy_name=policy_name,
                    condition_name=condition["name"],
                )
            else:
                title = TITLE_TEMPLATE_WARNING.format(
                    policy_name=policy_name,
                    condition_name=condition["name"],
                )

            # ── Rule 6: Threshold & operator conversion ────────────────────────
            nr_operator = term.get("operator", "ABOVE").upper()
            operator_rule = OPERATOR_RULES.get(nr_operator)

            if operator_rule is None:
                logger.warning(f"Unknown operator '{nr_operator}' — skipping term.")
                continue

            dt_condition, threshold_adj, needs_usf = operator_rule
            base_threshold = float(term.get("threshold", 0))

            # Rules 6.5 / 6.6: Do not convert — flag for USF review
            if needs_usf:
                self._flag_usf_review(
                    condition, policy_name, term, nr_operator
                )
                continue

            # Apply threshold adjustment (Rules 6.2 and 6.4)
            final_threshold = base_threshold + threshold_adj

            # ── Rules 6.7 / 6.8: Violating samples & sliding window ───────────
            occurrence_type  = term.get("thresholdOccurrences", "ALL").upper()
            threshold_dur_s  = int(term.get("thresholdDuration", window_duration_s))

            violating_samples, sliding_window = self._compute_samples(
                occurrence_type, window_duration_s, threshold_dur_s
            )
            violating_samples = max(1, min(60, violating_samples))
            sliding_window = max(1, min(60, sliding_window))
            #dealerting_samples = max(1, min(60, violating_samples))
            dealerting_samples = 1  # Rule 6.10: Use 1 sample for dealerting to avoid long recovery times


            # ── Rule 7: Event description ──────────────────────────────────────
            description = EVENT_DESCRIPTION_TEMPLATE.format(
                threshold=final_threshold,
                severity=priority,
            )

            # ── Rule 8: Event properties ───────────────────────────────────────
            priority_value = PRIORITY_MAP.get(priority, "P3")
            if dql_result["needs_manual_review"]:
                logger.warning(
                    f"Condition '{condition['name']}' is using a best-effort DQL conversion."
                )

            event_properties = [
                {"key": "dt.source_entity", "value": "{dims:dt.source_entity}"},
                {"key": "event.type", "value": EVENT_TYPE},
                {"key": "event.name", "value": title},
                {"key": "event.description", "value": "Problem exceeded threshold {threshold} with severity {severity}"},
                {"key": "priority", "value": priority_value},
                {"key": "email_addresses_comma", "value": email},
                {"key": "support_group", "value": support_group},
                {"key": "runbookUrl", "value": condition.get("runbookUrl") or ""},
                {"key": "alert_group", "value": ALERT_GROUP},
            ]
            event_properties = [
                item for item in event_properties
                if str(item.get("value", "")).strip()
            ]

            payload = {
                "schemaId": self.schema_ids["metric_event"],
                "schemaVersion": self.schema_versions["metric_event"],
                "scope": "environment",
                "value": {
                    "title":       title,
                    #"enabled":     condition.get("enabled", True),
                    "enabled":     False,
                    "description": description,
                    "source": "MigratedFromNewRelic"+datetime.datetime.now().strftime("%Y%m%d"),
                    "executionSettings": {
                        "actor": actor_id,
                    },
                    "analyzer": {
                        "name": (
                            "dt.statistics.ui.anomaly_detection."
                            "StaticThresholdAnomalyDetectionAnalyzer"
                        ),
                        "input": [
                            {"key": "query.expression", "value": dql_result["dql"]},
                            {"key": "alertOnMissingData", "value": "false"},
                            {"key": "violatingSamples", "value": str(violating_samples)},
                            {"key": "threshold", "value": str(final_threshold)},
                            {"key": "dealertingSamples", "value": str(dealerting_samples)},
                            {"key": "slidingWindow", "value": str(sliding_window)},
                            {"key": "alertCondition", "value": dt_condition},
                        ],
                    },
                    "eventTemplate": {
                        "properties": event_properties,
                    },
                },

                # Migration metadata kept outside value so DT API ignores it
                "_meta": {
                    "nr_condition_id":     condition["id"],
                    "nr_policy":           policy_name,
                    "nr_nrql":             nrql,
                    "nr_term_priority":    priority,
                    "nr_operator":         nr_operator,
                    "nr_threshold":        base_threshold,
                    "nr_threshold_occurrences": occurrence_type,
                    "nr_threshold_duration_s": threshold_dur_s,
                    "dt_alert_condition":  dt_condition,
                    "dt_threshold":        final_threshold,
                    "rule_operator_category": self._operator_rule_label(nr_operator),
                    "rule_occurrence_category": self._occurrence_rule_label(occurrence_type),
                    "violating_samples":   violating_samples,
                    "dealerting_samples":  dealerting_samples,
                    "sliding_window":      sliding_window,
                    "dql_warnings":        dql_result.get("warnings", []),
                    "needs_manual_review": dql_result.get("needs_manual_review", False),
                },
            }

            if alerting_profile_id:
                payload["_meta"]["alerting_profile_id"] = alerting_profile_id

            payload_signature = (
                payload["value"].get("title", ""),
                payload["value"].get("enabled", True),
                payload["value"].get("description", ""),
                payload["value"]["analyzer"]["name"],
                tuple(
                    (item.get("key", ""), item.get("value", ""))
                    for item in payload["value"]["analyzer"].get("input", [])
                ),
            )
            if payload_signature in seen_payload_signatures:
                logger.info(
                    "Skipping duplicate Dynatrace payload for condition '%s' in policy '%s'.",
                    condition["name"],
                    policy_name,
                )
                continue
            seen_payload_signatures.add(payload_signature)

            results.append(payload)

            # Log warnings from DQL conversion
            for warning in dql_result.get("warnings", []):
                logger.warning(f"  DQL conversion warning [{condition['name']}]: {warning}")

        return results

    def map_channel_to_notification(
        self, channel: dict, alerting_profile_id: str
    ) -> dict | None:
        """Convert a New Relic notification channel into Dynatrace notification payload format."""
        ch_type = channel.get("type", "").upper()
        base = {
            "schemaId": self.schema_ids["notification"],
            "scope":    "environment",
            "value": {
                "displayName":     channel["name"],
                "alertingProfile": alerting_profile_id,
                "active":          True,
            },
        }

        if ch_type == "EMAIL":
            cfg = channel.get("config", {})
            base["value"].update({
                "type":    "EMAIL",
                "subject": "{ProblemTitle} - {State} (migrated from New Relic)",
                "body":    "{ProblemDetailsHTML}",
                "to":      cfg.get("emails", []),
                "cc":      [],
                "bcc":     [],
            })
        elif ch_type == "SLACK":
            cfg = channel.get("config", {})
            base["value"].update({
                "type":    "SLACK",
                "url":     cfg.get("url", ""),
                "channel": cfg.get("teamChannel", ""),
                "message": "{ProblemTitle} ({State}) - {ProblemURL}",
            })
        elif ch_type == "PAGERDUTY":
            cfg = channel.get("config", {})
            base["value"].update({
                "type":        "PAGER_DUTY",
                "serviceKey":  cfg.get("serviceKey", ""),
                "account":     "",
                "serviceName": channel["name"],
                "receiver":    "",
            })
        elif ch_type == "WEBHOOK":
            cfg = channel.get("config", {})
            base["value"].update({
                "type":    "WEBHOOK",
                "url":     cfg.get("baseUrl", ""),
                "secret":  "",
                "headers": self._parse_headers(cfg.get("headers", {})),
                "payload": cfg.get("payload", "{}"),
                "acceptAnyCertificate": False,
            })
        else:
            logger.warning(f"Unsupported channel type '{ch_type}' — skipping.")
            return None

        return base

    # ── Private Helpers ────────────────────────────────────────────────────────

    def _compute_samples(
        self,
        occurrence_type: str,
        window_duration_s: int,
        threshold_duration_s: int,
    ) -> tuple[int, int]:
        """
        Rules 6.7 / 6.8: Compute violating_samples and sliding_window.

        Rule 6.7 — "for at least" (ALL occurrences):
          violating_samples == sliding_window == threshold_duration / window_duration
          Example: window=2m, threshold=4m → samples=2, window=2

        Rule 6.8 — "at least once in" (AT_LEAST_ONCE):
          violating_samples = 1, sliding_window = threshold_duration / window_duration
          Example: window=2m, threshold=4m → samples=1, window=2
        """
        if window_duration_s <= 0:
            window_duration_s = 60

        multiplier = max(1, threshold_duration_s // window_duration_s)

        if occurrence_type == "ALL":
            # Rule 6.7: for at least → samples == window
            return multiplier, multiplier
        else:
            # Rule 6.8: at least once in → samples=1, window=multiplier
            return 1, multiplier

    @staticmethod
    def _operator_rule_label(nr_operator: str) -> str:
        """Return the rule id for the given NR operator."""
        return {
            "ABOVE": "6.1",
            "ABOVE_OR_EQUALS": "6.2",
            "BELOW": "6.3",
            "BELOW_OR_EQUALS": "6.4",
            "EQUALS": "6.5",
            "NOT_EQUALS": "6.6",
        }.get(nr_operator.upper(), "UNKNOWN")

    @staticmethod
    def _occurrence_rule_label(occurrence_type: str) -> str:
        """Return the rule id for the given NR threshold occurrence mode."""
        if occurrence_type.upper() == "ALL":
            return "6.7"
        return "6.8"

    @staticmethod
    def _seconds_to_duration(seconds: int) -> str:
        """Convert seconds to a short duration string used in generated metadata."""
        if seconds < 60:
            return f"{seconds}s"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m"
        return f"{minutes // 60}h"

    def _flag_usf_review(
        self,
        condition: dict,
        policy_name: str,
        term: dict,
        nr_operator: str,
    ) -> None:
        """
        Record a condition term that still cannot be translated safely.

        This helper is bookkeeping-only; the caller decides whether to skip the
        current term after the review entry is recorded.
        """
        entry = {
            "policy_name":    policy_name,
            "condition_id":   condition.get("id"),
            "condition_name": condition.get("name"),
            "operator":       nr_operator,
            "threshold":      term.get("threshold"),
            "priority":       term.get("priority"),
            "reason": (
                f"Operator '{nr_operator}' has no direct DT equivalent "
                f"(Rules 6.5/6.6) — manual conversion required."
            ),
        }
        self.usf_review_items.append(entry)
        logger.warning(
            f"USF review required: condition '{condition.get('name')}' "
            f"uses operator '{nr_operator}' which cannot be auto-migrated."
        )

    @staticmethod
    def _parse_headers(headers_raw: dict | list) -> list[dict]:
        """
        Normalize webhook headers into the list-of-dicts shape expected by the
        Dynatrace notification API.
        """
        if isinstance(headers_raw, list):
            # Already in list form — ensure correct key names
            result = []
            for h in headers_raw:
                if isinstance(h, dict):
                    name  = h.get("name") or h.get("key") or ""
                    value = h.get("value", "")
                    if name:
                        result.append({"name": name, "value": value})
            return result

        # Dict form
        return [
            {"name": k, "value": v}
            for k, v in (headers_raw or {}).items()
        ]
