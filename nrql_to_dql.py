"""
NRQL to DQL conversion engine.
Implements Rules 4, 4.1, 4.2, 4.3, 4.4 from the migration rules document.
"""

import re
import logging
from migration_rules import (
    LOG_COLUMN_MAP,
    SPAN_COLUMN_MAP,
    GENERAL_COLUMN_MAP,
)

logger = logging.getLogger(__name__)


class NRQLtoDQLConverter:
    """
    Converts New Relic NRQL queries to Dynatrace DQL queries.

    Supported NRQL patterns:
      SELECT <aggregation>(<metric>) FROM <table>
        [WHERE <conditions>]
        [FACET <dimension>]
        [SINCE <time>]
    """

    # Aggregation function mapping
    AGG_MAP = {
        "average":    "avg",
        "avg":        "avg",
        "sum":        "sum",
        "count":      "count",
        "min":        "min",
        "max":        "max",
        "uniqueCount": "countDistinct",
        "percentile": "percentile",
        "rate":       "rate",
        "latest":     "last",
        "stddev":     "stddev",
    }

    # NR table → DT table mapping
    TABLE_MAP = {
        "Metric":       "metrics",
        "Transaction":  "spans",
        "TransactionError": "spans",
        "Span":         "spans",
        "AjaxRequest":  "spans",
        "Log":          "logs",
        "SystemSample": "metrics",
        "ProcessSample": "metrics",
        "NetworkSample": "metrics",
        "StorageSample": "metrics",
        "K8sContainerSample": "spans",
        "K8sJobSample": "spans",
        "BrowserInteraction": "spans",
        "PageAction":   "spans",
        "SyntheticCheck": "synthetics",
        "SyntheticsPrivateLocationStatus": "synthetics",
        "NrAiIncident": "events",
    }

    def convert(
        self,
        nrql: str,
        window_duration_seconds: int = 60,
        delay_seconds: int = 0,
        condition_name: str = "",
    ) -> dict:
        """
        Convert NRQL to DQL.

        Returns:
            {
              "dql": str,
              "interval": str,   # e.g. "1m"
              "delay": str,      # e.g. "1m"
              "warnings": list,
              "needs_manual_review": bool,
            }
        """
        result = {
            "dql": "",
            "interval": self._seconds_to_duration(window_duration_seconds),
            "delay": self._seconds_to_duration(window_duration_seconds),  # Rule 4.2
            "warnings": [],
            "needs_manual_review": False,
        }

        nrql = nrql.strip()
        logger.debug(f"Converting NRQL: {nrql}")

        # Detect table type
        table = self._extract_table(nrql)
        dt_table = self.TABLE_MAP.get(table, None)

        if dt_table is None:
            select_clause = self._extract_select_clause(nrql)
            if (
                "count(*)" not in select_clause.lower()
                and "count()" not in select_clause.lower()
                and re.search(r"\b(latest|average|avg|sum|min|max|percentile)\s*\(", select_clause, re.IGNORECASE)
            ):
                result["warnings"].append(
                    f"Unknown NRQL table '{table}' - using a best-effort metrics conversion."
                )
                result["needs_manual_review"] = True
                dt_table = "metrics"
            else:
                result["warnings"].append(
                    f"Unknown NRQL table '{table}' - using a best-effort spans conversion."
                )
                result["needs_manual_review"] = True
                dt_table = "spans"

        manual_review_reason = self._get_manual_review_reason(nrql, table, dt_table)
        if manual_review_reason:
            result["warnings"].append(manual_review_reason)
            result["needs_manual_review"] = True

        # Route to specific converter
        if dt_table == "spans":
            dql = self._convert_spans(nrql, window_duration_seconds, result)
        elif dt_table == "logs":
            dql = self._convert_logs(nrql, window_duration_seconds, result)
        elif dt_table == "metrics":
            dql = self._convert_metrics(nrql, window_duration_seconds, result)
        elif dt_table == "synthetics":
            dql = self._convert_synthetics(nrql, window_duration_seconds, result)
        else:
            result["warnings"].append(
                f"Table '{dt_table}' conversion not fully automated."
            )
            result["needs_manual_review"] = True
            dql = f"// TODO: Manual conversion for table '{dt_table}'\n// NRQL: {nrql}"
        dql = dql.replace("container_name","k8s.container.name")
        dql = dql.replace("containerName","k8s.container.name")
        result["dql"] = dql
        return result

    # ── Span Conversion (Rule 4.4) ─────────────────────────────────────────────

    def _convert_spans(self, nrql: str, window_seconds: int, result: dict) -> str:
        """
        Example:
          NRQL: SELECT average(duration.ms) FROM Span
                WHERE entity.name = 'prod-usf-price-integration-api'
                AND http.route = '/price' AND http.method = 'POST'
                FACET host.name
          DQL:  fetch spans
                | filter dt.service.name == "prod-usf-price-integration-api"
                  and http.route == "/price" and http.method == "POST"
                | makeTimeseries avg(duration), by:{host.name}, interval:1m
        """
        interval_str = self._seconds_to_duration(window_seconds)

        guarded_span_percentage_expression = self._build_guarded_span_percentage_expression(
            nrql=nrql,
            interval_str=interval_str,
        )
        if guarded_span_percentage_expression is not None:
            return guarded_span_percentage_expression

        span_percentage_expression = self._build_span_percentage_expression(
            nrql=nrql,
            interval_str=interval_str,
        )
        if span_percentage_expression is not None:
            return span_percentage_expression

        # Extract aggregation
        agg_func, agg_col = self._extract_aggregation(nrql)
        # Map column names (Rule 4.4)
        agg_col_mapped = SPAN_COLUMN_MAP.get(agg_col, agg_col)
        dt_agg_func    = self.AGG_MAP.get(agg_func.lower(), agg_func.lower())

        # Extract WHERE clause and convert
        where_clause = self._extract_last_where_before_facet(nrql) if "K8sJobSample" in nrql else self._extract_where(nrql)
        dt_filter    = self._convert_where_clause(where_clause, SPAN_COLUMN_MAP, "spans")

        # Extract FACET
        facet_cols   = self._extract_facet(nrql)
        facet_mapped = [SPAN_COLUMN_MAP.get(c.strip(), c.strip()) for c in facet_cols]

        # Build DQL
        lines = ["fetch spans"]

        if dt_filter:
            lines.append(f"| filter {dt_filter}")

        if "K8sJobSample" in nrql or "filter(count(" in nrql.lower():
            timeseries_parts = ["request_count = count()"]
            result["warnings"].append(
                "Approximated nested K8s job query as a count-based timeseries."
            )
        else:
            timeseries_parts = [self._build_span_or_log_expression(nrql, dt_agg_func, agg_col_mapped)]
        if facet_mapped:
            by_clause = ", ".join(f"{c}" for c in facet_mapped)
            timeseries_parts.append(f"by:{{{by_clause}}}")
        timeseries_parts.append(f"interval:{interval_str}")

        lines.append(f"| makeTimeseries {', '.join(timeseries_parts)}")

        return "\n".join(lines)

    # ── Log Conversion (Rule 4.3) ──────────────────────────────────────────────

    def _convert_logs(self, nrql: str, window_seconds: int, result: dict) -> str:
        """
        Converts Log queries applying "data." prefix rules (Rule 4.3).
        """
        interval_str = self._seconds_to_duration(window_seconds)

        # Extract aggregation
        agg_func, agg_col = self._extract_aggregation(nrql)
        agg_col_mapped = LOG_COLUMN_MAP.get(agg_col, agg_col)
        dt_agg_func    = self.AGG_MAP.get(agg_func.lower(), agg_func.lower())

        # Extract WHERE and convert using log column map
        where_clause = self._extract_where(nrql)
        dt_filter    = self._convert_where_clause(where_clause, LOG_COLUMN_MAP, "logs")

        # Extract FACET
        facet_cols   = self._extract_facet(nrql)
        facet_mapped = [LOG_COLUMN_MAP.get(c.strip(), c.strip()) for c in facet_cols]

        lines = ["fetch logs"]

        if dt_filter:
            lines.append(f"| filter {dt_filter}")

        timeseries_parts = [self._build_span_or_log_expression(nrql, dt_agg_func, agg_col_mapped)]
        if facet_mapped:
            by_clause = ", ".join(facet_mapped)
            timeseries_parts.append(f"by:{{{by_clause}}}")
        timeseries_parts.append(f"interval:{interval_str}")

        lines.append(f"| makeTimeseries {', '.join(timeseries_parts)}")

        return "\n".join(lines)

    # ── Metrics Conversion ─────────────────────────────────────────────────────

    def _convert_metrics(self, nrql: str, window_seconds: int, result: dict) -> str:
        """
        Converts Metric/SystemSample queries to DQL timeseries.
        """
        interval_str = self._seconds_to_duration(window_seconds)

        where_clause = self._extract_where(nrql)
        dt_filter    = self._convert_where_clause(where_clause, GENERAL_COLUMN_MAP, "metrics")

        facet_cols   = self._extract_facet(nrql)
        facet_mapped = [GENERAL_COLUMN_MAP.get(c.strip(), c.strip()) for c in facet_cols]

        metric_percent_expression = self._build_metric_percent_expression(
            nrql=nrql,
            dt_filter=dt_filter,
            facet_mapped=facet_mapped,
            interval_str=interval_str,
        )
        if metric_percent_expression is not None:
            return metric_percent_expression

        timeseries_parts = [self._build_metric_expression(nrql, result)]
        if facet_mapped:
            by_clause = ", ".join(facet_mapped)
            timeseries_parts.append(f"by:{{{by_clause}}}")
        if dt_filter:
            timeseries_parts.append(f"filter:{{{dt_filter}}}")
        timeseries_parts.append(f"interval:{interval_str}")

        return f"timeseries {', '.join(timeseries_parts)}"

    def _convert_synthetics(self, nrql: str, window_seconds: int, result: dict) -> str:
        """
        Best-effort conversion for SyntheticCheck queries.
        """
        result["warnings"].append(
            "SyntheticCheck was converted to a plain synthetic entity fetch because the broader timeseries form was rejected."
        )
        return "fetch dt.entity.external_synthetic_test"

    # ── WHERE Clause Converter ─────────────────────────────────────────────────

    def _convert_where_clause(
        self,
        where: str,
        column_map: dict,
        table_type: str,
    ) -> str:
        """
        Converts NRQL WHERE clause to DQL filter expression.
        - Maps column names using the provided column_map
        - Converts NRQL operators to DQL operators
        - Handles AND / OR / NOT / IN / LIKE / IS NULL
        """
        if not where:
            return ""

        expr = where.strip()

        # Operator conversions
        expr = re.sub(r"(\S+)\s+IS\s+TRUE", r"\1 == true", expr, flags=re.IGNORECASE)
        expr = re.sub(r"(\S+)\s+IS\s+FALSE", r"\1 == false", expr, flags=re.IGNORECASE)
        expr = re.sub(r"(\S+)\s+IS\s+NOT\s+NULL", r"isNotNull(\1)", expr, flags=re.IGNORECASE)
        expr = re.sub(r"(\S+)\s+IS\s+NULL", r"isNull(\1)", expr, flags=re.IGNORECASE)
        expr = re.sub(
            r"(\S+)\s+NOT\s+LIKE\s+'([^']*)'",
            self._replace_not_like_clause,
            expr,
            flags=re.IGNORECASE,
        )
        expr = re.sub(
            r"(\S+)\s+LIKE\s+'([^']*)'",
            self._replace_like_clause,
            expr,
            flags=re.IGNORECASE,
        )
        expr = re.sub(r"(\S+)\s+NOT\s+IN\s*\(([^)]+)\)", self._replace_not_in_clause, expr, flags=re.IGNORECASE)
        expr = re.sub(r"(\S+)\s+IN\s*\(([^)]+)\)", self._replace_in_clause, expr, flags=re.IGNORECASE)
        expr = re.sub(r"(?<![!<>=~])=(?!(=|~))", " == ", expr)
        expr = re.sub(r"\bAND\b",         "and",     expr, flags=re.IGNORECASE)
        expr = re.sub(r"\bOR\b",          "or",      expr,  flags=re.IGNORECASE)
        expr = re.sub(r"\bWHERE\b", "and", expr, flags=re.IGNORECASE)
        expr = re.sub(r"!\s*==", "!=", expr)
        expr = re.sub(r"\bnumeric\s*\(\s*([^)]+?)\s*\)", r"\1", expr, flags=re.IGNORECASE)
        expr = re.sub(r"isNull\(\(([^)]+)\)\)", r"isNull(\1)", expr)
        expr = re.sub(r"isNotNull\(\(([^)]+)\)\)", r"isNotNull(\1)", expr)
        expr = re.sub(r"\(\(([^()]+)\)\)", r"(\1)", expr)

        # Replace single-quoted strings with double-quoted
        expr = re.sub(r"'([^']*)'", r'"\1"', expr)

        # Apply column name mappings (longest match first to avoid partial replacements)
        sorted_keys = sorted(column_map.keys(), key=len, reverse=True)
        for nr_col in sorted_keys:
            dt_col = column_map[nr_col]
            # Word-boundary aware replacement
            expr = re.sub(
                rf"(?<![.\w]){re.escape(nr_col)}(?![.\w])",
                dt_col,
                expr,
            )

        expr = re.sub(r"`([A-Za-z0-9_.:]+)`", lambda match: match.group(1) if "." in match.group(1) else match.group(0), expr)
        expr = re.sub(
            r'([A-Za-z]+)\(\(([^,()]+), "([^"]*)"\)\s+or\s+\1\(\2, "([^"]*)"\)\)',
            r'(\1(\2, "\3") or \1(\2, "\4"))',
            expr,
        )
        expr = re.sub(r'([A-Za-z]+)\(\(\s*([A-Za-z0-9_.`]+)\s*,', r'(\1(\2,', expr)
        expr = re.sub(r'"\)\)\s*', '")) ', expr)
        expr = re.sub(r'"\)\s*and\b', '") and', expr)
        expr = re.sub(r'"\)\s*or\b', '") or', expr)
        expr = self._balance_parentheses(expr)

        return expr.strip()

    def _replace_in_clause(self, match: re.Match) -> str:
        """Expand `field IN (...)` into chained equality expressions for DQL."""
        field = match.group(1).strip().strip("()")
        values = self._split_list_values(match.group(2))
        clauses = [f"{field} == {value}" for value in values]
        return clauses[0] if len(clauses) == 1 else "(" + " or ".join(clauses) + ")"

    def _replace_not_in_clause(self, match: re.Match) -> str:
        """Expand `field NOT IN (...)` into chained inequality expressions for DQL."""
        field = match.group(1).strip().strip("()")
        values = self._split_list_values(match.group(2))
        clauses = [f"{field} != {value}" for value in values]
        return clauses[0] if len(clauses) == 1 else "(" + " and ".join(clauses) + ")"

    def _replace_like_clause(self, match: re.Match) -> str:
        """Translate NRQL LIKE into the closest supported DQL string function."""
        return self._replace_like_match(match, negate=False)

    def _replace_not_like_clause(self, match: re.Match) -> str:
        """Translate NRQL NOT LIKE into the closest supported DQL string function."""
        return self._replace_like_match(match, negate=True)

    def _replace_like_match(self, match: re.Match, negate: bool) -> str:
        """Convert wildcard string matching into startsWith/contains/endsWith logic."""
        field = match.group(1).strip()
        pattern = match.group(2).replace("%%", "%").strip()

        if pattern.startswith("%") and pattern.endswith("%") and len(pattern) >= 2:
            return self._wrap_negation(f'contains({field}, "{pattern[1:-1]}")', negate)
        if pattern.endswith("%"):
            return self._wrap_negation(f'startsWith({field}, "{pattern[:-1]}")', negate)
        if pattern.startswith("%"):
            return self._wrap_negation(f'endsWith({field}, "{pattern[1:]}")', negate)

        operator = "!=" if negate else "=="
        return f'{field} {operator} "{pattern}"'

    def _wrap_negation(self, expression: str, negate: bool) -> str:
        """Apply a leading DQL negation when a NOT-like pattern is requested."""
        return f"not {expression}" if negate else expression

    def _convert_duration_ms_thresholds(self, expr: str) -> str:
        """Convert span duration thresholds from milliseconds to nanoseconds."""
        def replacer(match: re.Match) -> str:
            operator = match.group(1)
            raw_value = match.group(2)
            nanoseconds = int(float(raw_value) * 1_000_000)
            return f"duration {operator} {nanoseconds}"

        return re.sub(
            r"\bduration\s*(<=|>=|==|!=|<|>)\s*([0-9]+(?:\.[0-9]+)?)",
            replacer,
            expr,
        )

    def _balance_parentheses(self, expr: str) -> str:
        """Trim trailing unmatched right parentheses introduced during regex rewriting."""
        open_count = expr.count("(")
        close_count = expr.count(")")
        while close_count > open_count and expr.endswith(")"):
            expr = expr[:-1].rstrip()
            close_count -= 1
        return expr

    def _split_list_values(self, values: str) -> list[str]:
        """Split a comma-separated literal list while preserving quoted values."""
        parts = []
        current = ""
        quote_char = None

        for char in values:
            if char in ("'", '"'):
                if quote_char is None:
                    quote_char = char
                elif quote_char == char:
                    quote_char = None
                current += char
            elif char == "," and quote_char is None:
                if current.strip():
                    parts.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            parts.append(current.strip())

        return parts


    def _build_timeseries_expression(self, func: str, col: str) -> str:
        """Build the common `makeTimeseries` expression for span/log aggregations."""
        if func == "count":
            return "request_count = count()"
        return f"value = {func}({col})"

    def _build_span_or_log_expression(self, nrql: str, func: str, col: str) -> str:
        """Build a span/log expression with special handling for percentile syntax."""
        if func == "percentile":
            percentile_value = self._extract_percentile_value(nrql)
            if percentile_value is not None:
                return f"value = percentile({col}, {percentile_value})"
        return self._build_timeseries_expression(func, col)

    def _build_span_percentage_expression(self, nrql: str, interval_str: str) -> str | None:
        """
        Convert span percentage queries into a `countIf` timeseries.

        Example source:
        FROM Span SELECT percentage(count(), where duration.ms <= 1000) WHERE ...
        """
        select_clause = self._extract_select_clause(nrql)
        match = re.search(
            r"percentage\s*\(\s*count\(\s*(?:\*)?\s*\)\s*,\s*where\s+(.+?)\s*\)\s*$",
            select_clause,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            return None

        inner_where = match.group(1).strip()
        outer_where = self._extract_where(nrql)

        dt_filter = self._convert_where_clause(outer_where, SPAN_COLUMN_MAP, "spans")
        dt_inner_condition = self._convert_where_clause(inner_where, SPAN_COLUMN_MAP, "spans")
        dt_inner_condition = self._convert_duration_ms_thresholds(dt_inner_condition)

        lines = ["fetch spans"]
        if dt_filter:
            lines.append(f"| filter {dt_filter}")
        lines.append(
            f"| makeTimeseries total = count(), within_slo = countIf({dt_inner_condition}), interval:{interval_str}"
        )
        lines.append("| fieldsAdd percentage = (within_slo / toDouble(total)) * 100")
        return "\n".join(lines)

    def _build_guarded_span_percentage_expression(self, nrql: str, interval_str: str) -> str | None:
        """
        Convert span queries shaped like:
        if(count(*) > N, percentage(count(*), where duration.ms <= X), fallback)
        """
        select_clause = self._extract_select_clause(nrql)
        compact_select = " ".join(select_clause.replace("\xa0", " ").split())
        match = re.search(
            r"if\s*\(\s*count\(\s*(?:\*)?\s*\)\s*>\s*([0-9]+(?:\.[0-9]+)?)\s*,\s*"
            r"percentage\s*\(\s*count\(\s*(?:\*)?\s*\)\s*,\s*where\s+(.+?)\s*\)\s*,\s*"
            r"([0-9]+(?:\.[0-9]+)?)\s*\)"
            r"(?:\s+as\s+[`'\"]?[\w .-]+[`'\"]?)?\s*$",
            compact_select,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            return None

        minimum_count = match.group(1).strip()
        inner_where = match.group(2).strip()
        fallback_value = match.group(3).strip()
        outer_where = self._extract_where(nrql)

        dt_filter = self._convert_where_clause(outer_where, SPAN_COLUMN_MAP, "spans")
        dt_inner_condition = self._convert_where_clause(inner_where, SPAN_COLUMN_MAP, "spans")
        dt_inner_condition = self._convert_duration_ms_thresholds(dt_inner_condition)

        lines = ["fetch spans"]
        if dt_filter:
            lines.append(f"| filter {dt_filter}")
        lines.append(
            f"| makeTimeseries total = count(), within_slo = countIf({dt_inner_condition}), interval:{interval_str}"
        )
        lines.append(
            f"| fieldsAdd acceptable_resp_percent = if(toDouble(total) > {minimum_count}, "
            f"(within_slo / toDouble(total)) * 100, {fallback_value})"
        )
        return "\n".join(lines)

    def _build_metric_timeseries_expression(self, func: str, col: str) -> str:
        """Build the metric expression portion of a Davis-compatible `timeseries` query."""
        if func == "count":
            if col == "*":
                return "request_count = count()"
            return f"value = count({col})"
        if func == "last":
            return f"value = max({col})"
        return f"value = {func}({col})"

    def _build_metric_expression(self, nrql: str, result: dict) -> str:
        """Convert the metric SELECT clause into a best-effort Dynatrace expression."""
        select_clause = self._extract_select_clause(nrql)

        sum_unique_percent_match = self._match_sum_unique_count_percent(select_clause)
        if sum_unique_percent_match:
            numerator, denominator, multiplier = sum_unique_percent_match
            numerator = self._map_metric_identifier(numerator)
            denominator = self._map_metric_identifier(denominator)
            return (
                f"value = (sum({numerator}) / "
                f"countDistinct({denominator}) * {multiplier})"
            )

        rate_sum_match = re.search(
            r"rate\s*\(\s*sum\s*\(\s*([^)]+?)\s*\)\s*,",
            select_clause,
            re.IGNORECASE,
        )
        if rate_sum_match:
            field = GENERAL_COLUMN_MAP.get(rate_sum_match.group(1).strip(), rate_sum_match.group(1).strip())
            result["warnings"].append(
                "Approximated rate(sum(metric), window) as sum(metric) per interval."
            )
            return f"value = sum({field})"

        rate_count_match = re.search(
            r"rate\s*\(\s*count\s*\(\s*([^)]+?)\s*\)\s*,",
            select_clause,
            re.IGNORECASE,
        )
        if rate_count_match:
            field = GENERAL_COLUMN_MAP.get(rate_count_match.group(1).strip(), rate_count_match.group(1).strip())
            result["warnings"].append(
                "Approximated rate(count(metric), window) as count(metric) per interval."
            )
            return f"value = count({field})"

        ratio_match = re.search(
            r"count\s*\(\s*([^)]+?)\s*\)\s*/\s*count\s*\(\s*([^)]+?)\s*\)",
            select_clause,
            re.IGNORECASE,
        )
        if ratio_match:
            numerator = ratio_match.group(1).strip()
            field = GENERAL_COLUMN_MAP.get(numerator, numerator)
            result["warnings"].append(
                "Approximated metric ratio using the numerator count only."
            )
            return f"value = count({field})"

        agg_func, agg_col = self._extract_aggregation(nrql)
        agg_col_mapped = GENERAL_COLUMN_MAP.get(agg_col, agg_col)
        dt_agg_func = self.AGG_MAP.get(agg_func.lower(), agg_func.lower())
        if dt_agg_func == "last":
            result["warnings"].append(
                "Approximated latest(metric) as max(metric) for metric-based timeseries compatibility."
            )
        if dt_agg_func == "percentile":
            percentile_value = self._extract_percentile_value(nrql)
            if percentile_value is not None:
                return f"value = percentile({agg_col_mapped}, {percentile_value})"
        return self._build_metric_timeseries_expression(dt_agg_func, agg_col_mapped)

    def _build_metric_percent_expression(
        self,
        nrql: str,
        dt_filter: str,
        facet_mapped: list[str],
        interval_str: str,
    ) -> str | None:
        """
        Build a two-series metric expression for percentage-style queries such as:
        SUM(metric) / uniqueCount(dimension) * 100

        Dynatrace rejects the earlier arithmetic `timeseries value = (...)` form for
        Davis anomaly detectors, so this emits a multi-series timeseries followed by
        a derived `value` field.
        """
        select_clause = self._extract_select_clause(nrql)
        sum_unique_percent_match = self._match_sum_unique_count_percent(select_clause)
        if not sum_unique_percent_match:
            return None

        numerator, denominator, multiplier = sum_unique_percent_match
        numerator = self._map_metric_identifier(numerator)
        denominator = self._map_metric_identifier(denominator)

        by_fields = list(facet_mapped)
        for candidate in ("k8s.cluster.name", "k8s.workload.name"):
            if candidate in dt_filter and candidate not in by_fields:
                by_fields.append(candidate)

        timeseries_lines = [
            "timeseries {",
            f"    numerator = sum({numerator}, rate: {interval_str}),",
            f"    denominator = count({denominator})",
            "  },",
        ]
        if by_fields:
            by_clause = ", ".join(by_fields)
            timeseries_lines.append(f"  by: {{ {by_clause} }},")
        if dt_filter:
            timeseries_lines.append("  filter: {")
            timeseries_lines.extend(
                f"    {line.strip()}"
                for line in dt_filter.splitlines()
                if line.strip()
            )
            timeseries_lines.append("  }")
        else:
            timeseries_lines[-1] = timeseries_lines[-1].rstrip(",")

        timeseries_lines.append(f"| fieldsAdd value = (numerator[] / denominator[]) * {multiplier}")
        timeseries_lines.append("| fieldsRemove numerator, denominator")
        return "\n".join(timeseries_lines)

    def _get_manual_review_reason(self, nrql: str, table: str, dt_table: str | None) -> str | None:
        """Return a warning string for patterns that are converted only approximately."""
        select_clause = self._extract_select_clause(nrql)

        if re.search(r"\bFACET\s+CASES\b", nrql, re.IGNORECASE):
            return "FACET CASES is not converted safely; manual review required."
        if re.search(r"\bEXTRAPOLATE\b", nrql, re.IGNORECASE):
            return "EXTRAPOLATE is not supported by the converter; manual review required."
        if table == "SyntheticCheck":
            return "SyntheticCheck queries need manual review."
        if dt_table == "metrics":
            if re.search(r"\brate\s*\(", select_clause, re.IGNORECASE):
                return "Nested rate() metric expressions need manual review."
            if re.search(r"\bfilter\s*\(", select_clause, re.IGNORECASE):
                return "filter() metric expressions need manual review."
            if "/" in select_clause and not self._match_sum_unique_count_percent(select_clause):
                return "Metric ratio expressions need manual review."
        return None

    def _match_sum_unique_count_percent(self, select_clause: str) -> tuple[str, str, str] | None:
        """Recognize `sum(metric) / uniqueCount(dimension) * N` metric percentages."""
        match = re.search(
            r"^\s*\(?\s*sum\s*\(\s*([^)]+?)\s*\)\s*/\s*"
            r"uniqueCount\s*\(\s*([^)]+?)\s*\)\s*\*\s*([0-9.]+)"
            r"\s*\)?(?:\s+AS\s+[`'\"]?[\w .-]+[`'\"]?)?\s*$",
            select_clause,
            re.IGNORECASE,
        )
        if not match:
            return None
        return (
            match.group(1).strip(),
            match.group(2).strip(),
            match.group(3).strip(),
        )

    def _map_metric_identifier(self, identifier: str) -> str:
        """Normalize a metric or dimension identifier before placing it in DQL."""
        normalized = identifier.strip()
        unquoted = normalized.strip("`")
        return GENERAL_COLUMN_MAP.get(unquoted, normalized)

    # ── Extraction Helpers ─────────────────────────────────────────────────────

    def _extract_table(self, nrql: str) -> str:
        """Extract the NRQL table name that follows the FROM clause."""
        match = re.search(r"\bFROM\s+(\w+)", nrql, re.IGNORECASE)
        return match.group(1) if match else "Unknown"

    def _extract_aggregation(self, nrql: str) -> tuple[str, str]:
        """Returns (agg_function, column_name) from SELECT clause."""
        # Handles: SELECT average(duration.ms), count(), count(*), percentile(duration, 95)
        match = re.search(
            r"SELECT\s+(\w+)\(([^)]*)\)",
            nrql,
            re.IGNORECASE,
        )
        if match:
            func = match.group(1)
            col  = match.group(2).strip().split(",")[0].strip()  # first arg only
            return func, col
        return "avg", "value"

    def _extract_select_clause(self, nrql: str) -> str:
        """Return the raw SELECT body so downstream helpers can inspect it."""
        upper_nrql = nrql.upper()
        select_match = re.search(r"\bSELECT\b", upper_nrql)
        if not select_match:
            return ""

        start_index = select_match.end()
        depth = 0
        in_single_quote = False
        in_double_quote = False

        for index in range(start_index, len(nrql)):
            char = nrql[index]
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                continue
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                continue
            if in_single_quote or in_double_quote:
                continue
            if char == "(":
                depth += 1
                continue
            if char == ")":
                depth = max(0, depth - 1)
                continue
            if depth != 0:
                continue

            for keyword in ("FROM", "WHERE", "FACET", "SINCE", "UNTIL", "LIMIT", "TIMESERIES", "COMPARE"):
                if upper_nrql.startswith(keyword, index):
                    prev_ok = index == 0 or not upper_nrql[index - 1].isalnum()
                    next_index = index + len(keyword)
                    next_ok = next_index >= len(upper_nrql) or not upper_nrql[next_index].isalnum()
                    if prev_ok and next_ok:
                        return nrql[start_index:index].strip()

        return nrql[start_index:].strip()

    def _extract_percentile_value(self, nrql: str) -> str | None:
        """Extract the percentile argument from `percentile(metric, p)` if present."""
        match = re.search(r"percentile\s*\(\s*[^,]+,\s*([0-9.]+)\s*\)", nrql, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_where(self, nrql: str) -> str:
        """Extracts WHERE clause content (between WHERE and FACET/SINCE/LIMIT/TIMESERIES)."""
        upper_nrql = nrql.upper()
        depth = 0
        in_single_quote = False
        in_double_quote = False
        where_index = -1

        for index, char in enumerate(nrql):
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                continue
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                continue
            if in_single_quote or in_double_quote:
                continue
            if char == "(":
                depth += 1
                continue
            if char == ")":
                depth = max(0, depth - 1)
                continue

            if depth == 0 and upper_nrql.startswith("WHERE", index):
                prev_ok = index == 0 or not upper_nrql[index - 1].isalnum()
                next_index = index + len("WHERE")
                next_ok = next_index >= len(upper_nrql) or not upper_nrql[next_index].isalnum()
                if prev_ok and next_ok:
                    where_index = index
                    break

        if where_index == -1:
            return ""

        depth = 0
        in_single_quote = False
        in_double_quote = False
        start_index = where_index + len("WHERE")

        for index in range(start_index, len(nrql)):
            char = nrql[index]
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                continue
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                continue
            if in_single_quote or in_double_quote:
                continue
            if char == "(":
                depth += 1
                continue
            if char == ")":
                depth = max(0, depth - 1)
                continue
            if depth != 0:
                continue

            for keyword in ("FACET", "SINCE", "UNTIL", "LIMIT", "TIMESERIES", "COMPARE"):
                if upper_nrql.startswith(keyword, index):
                    prev_ok = index == 0 or not upper_nrql[index - 1].isalnum()
                    next_index = index + len(keyword)
                    next_ok = next_index >= len(upper_nrql) or not upper_nrql[next_index].isalnum()
                    if prev_ok and next_ok:
                        return nrql[start_index:index].strip()

        return nrql[start_index:].strip()

    def _extract_last_where_before_facet(self, nrql: str) -> str:
        """Pick the last outer WHERE before FACET for nested K8s job expressions."""
        upper_nrql = nrql.upper()
        where_index = upper_nrql.rfind(" WHERE ")
        if where_index != -1:
            facet_index = upper_nrql.find(" FACET ", where_index)
            search_end = facet_index if facet_index != -1 else len(nrql)
            return nrql[where_index + len(" WHERE "):search_end].strip()
        return self._extract_where(nrql)

    def _extract_facet(self, nrql: str) -> list[str]:
        """Extract the FACET column list while ignoring unsupported FACET CASES shapes."""
        match = re.search(
            r"\bFACET\b\s+(.+?)(?:\bWHERE\b|\bSINCE\b|\bUNTIL\b|\bLIMIT\b|\bTIMESERIES\b|$)",
            nrql,
            re.IGNORECASE | re.DOTALL,
        )
        if match:
            facet_expr = match.group(1).strip()
            facet_expr = re.split(r"\bWHERE\b|\bFACET\b", facet_expr, maxsplit=1, flags=re.IGNORECASE)[0]
            facet_expr = facet_expr.strip("() ").rstrip(")")
            if re.search(r"\bCASES\b|\bEXTRAPOLATE\b", facet_expr, re.IGNORECASE):
                return []
            return [c.strip() for c in facet_expr.split(",")]
        return []

    def _seconds_to_duration(self, seconds: int) -> str:
        """Convert seconds to a compact duration string such as `1m` or `2h`."""
        if seconds < 60:
            return f"{seconds}s"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m"
        hours = minutes // 60
        return f"{hours}h"
