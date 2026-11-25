"""
Migration rules as defined in:
  "Alert Condition Migration Rules New Relic to Dynatrace v1"
"""

# Rule 2/3: Alert/Event Title Templates
TITLE_TEMPLATE_CRITICAL = "{policy_name} - {condition_name} [CRITICAL]"
TITLE_TEMPLATE_WARNING = "{policy_name} - {condition_name} [WARNING]"

# Rule 7: Event Description
EVENT_DESCRIPTION_TEMPLATE = "Problem exceeded threshold {threshold} with severity {severity}"

# Rule 8: Event Properties
EVENT_TYPE = "CUSTOM_ALERT"
ALERT_GROUP = "MOXe"
PRIORITY_MAP = {
    "CRITICAL": "P2",
    "WARNING": "P3",
}

# Rule 4.3: Known Log column name mappings (NRQL -> DQL "data." prefix)
LOG_COLUMN_MAP = {
    "level": "data.level",
    "log.level": "data.log.level",
    "message": "data.message",
    "msg": "data.msg",
    "errorMessage": "data.errorMessage",
    "error.message": "data.error.message",
    "stackTrace": "data.stackTrace",
    "traceId": "data.traceId",
    "spanId": "data.spanId",
    "timestamp": "data.timestamp",
    "hostname": "data.hostname",
    "environment": "data.environment",
    "service": "data.service",
    "requestId": "data.requestId",
    "userId": "data.userId",
    "statusCode": "data.statusCode",
}

# Rule 4.4: Span column mappings (NRQL -> DQL)
SPAN_COLUMN_MAP = {
    "entity.name": "dt.service.name",
    "host": "host.name",
    "duration.ms": "duration",
    "host.name": "host.name",
    "service.name": "dt.service.name",
    "appName": "dt.application.name",
    "error.message": "error.message",
    "error.class": "error.type",
    "error.expected": "error.expected",
    "httpResponseCode": "httpResponseCode",
}

# Rule 4: General NRQL -> DQL column mappings
GENERAL_COLUMN_MAP = {
    "service.name": "dt.service.name",
    "entity.name": "dt.entity.name",
    "entity.guid": "dt.entity.id",
    "entityGuid": "dt.entity.id",
    "appName": "dt.application.name",
    "monitorName": "name",
    "checksPending": "checksPending",
    "k8s.clusterName": "k8s.cluster.name",
    "k8s.deploymentName": "k8s.workload.name",
    "k8s.container.restartCountDelta": "dt.kubernetes.container.restarts",
    "k8s.podName": "dt.kubernetes.pods",
}

# Rule 6.1-6.6: Operator conversion
# Format: (operator) -> (dt_condition, threshold_adjustment, needs_usf_review)
OPERATOR_RULES = {
    "ABOVE": ("ABOVE", 0, False),           # Rule 6.1
    "ABOVE_OR_EQUALS": ("ABOVE", -1, False),  # Rule 6.2
    "BELOW": ("BELOW", 0, False),           # Rule 6.3
    "BELOW_OR_EQUALS": ("BELOW", 1, False),   # Rule 6.4
    "EQUALS": (None, 0, True),             # Rule 6.5 - USF review only
    "NOT_EQUALS": (None, 0, True),         # Rule 6.6 - USF review only
}

# Rule 6.9: Analyzer
ANALYZER_TYPE = "STATIC_THRESHOLD"

# Supported NR occurrence types
OCCURRENCE_FOR_AT_LEAST = "ALL"             # Rule 6.7
OCCURRENCE_AT_LEAST_ONCE = "AT_LEAST_ONCE"  # Rule 6.8
