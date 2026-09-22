"""
Dynatrace problems reach Keep either through the webhook payload (State OPEN/RESOLVED, ProblemTitle)
or through the Problems API v2 (status OPEN/CLOSED, title/displayId). Both must map to the same
Keep status/severity/name so a problem that was pulled and later pushed stays one alert.
"""

import pytest

from keep.api.models.alert import AlertSeverity, AlertStatus
from keep.providers.dynatrace_provider.dynatrace_provider import DynatraceProvider


def _api_problem(**overrides):
    problem = {
        "problemId": "-3061187654246811781_1758550140000V2",
        "displayId": "P-2609315",
        "title": "High Memory",
        "impactLevel": "INFRASTRUCTURE",
        "severityLevel": "RESOURCE_CONTENTION",
        "status": "CLOSED",
        "startTime": 1758550140000,
        "endTime": 1758551520000,
        "entityTags": [],
        "impactedEntities": [],
    }
    problem.update(overrides)
    return problem


def test_api_closed_problem_is_resolved():
    alert = DynatraceProvider._format_alert(_api_problem())
    assert alert.status == AlertStatus.RESOLVED


def test_api_open_problem_is_firing():
    alert = DynatraceProvider._format_alert(_api_problem(status="OPEN"))
    assert alert.status == AlertStatus.FIRING


def test_api_problem_name_is_title_and_display_id_is_kept():
    alert = DynatraceProvider._format_alert(_api_problem())
    assert alert.name == "High Memory"
    assert alert.display_id == "P-2609315"
    assert "P-2609315" in alert.description


@pytest.mark.parametrize(
    "severity_level,expected",
    [
        ("AVAILABILITY", AlertSeverity.HIGH),
        ("ERROR", AlertSeverity.CRITICAL),
        ("PERFORMANCE", AlertSeverity.WARNING),
        ("RESOURCE_CONTENTION", AlertSeverity.WARNING),
        ("MONITORING_UNAVAILABLE", AlertSeverity.WARNING),
        ("CUSTOM_ALERT", AlertSeverity.INFO),
        ("SOMETHING_NEW", AlertSeverity.INFO),
    ],
)
def test_api_severity_mapping(severity_level, expected):
    alert = DynatraceProvider._format_alert(_api_problem(severityLevel=severity_level))
    assert alert.severity == expected


def test_webhook_payload_still_maps():
    event = {
        "ProblemID": "-3061187654246811781_1758550140000V2",
        "ProblemTitle": "High Memory",
        "State": "RESOLVED",
        "ProblemSeverity": "RESOURCE_CONTENTION",
        "ProblemImpact": "INFRASTRUCTURE",
        "ProblemURL": "https://ysa24221.apps.dynatrace.com/ui/apps/dynatrace.classic.problems/#problems/problemdetails;pid=x",
        "ImpactedEntities": [],
        "Tags": "",
    }
    alert = DynatraceProvider._format_alert(event)
    assert alert.status == AlertStatus.RESOLVED
    assert alert.severity == AlertSeverity.WARNING
    assert alert.name == "High Memory"
