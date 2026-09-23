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
        "impactedEntities": [{"entityId": {"id": "HOST-1", "type": "HOST"}, "name": "INFVPLAWS02"}],
        "affectedEntities": [{"entityId": {"id": "HOST-1", "type": "HOST"}, "name": "INFVPLAWS02"}],
        "rootCauseEntity": {"entityId": {"id": "PROCESS_GROUP-1", "type": "PROCESS_GROUP"}, "name": "Windows System"},
        "managementZones": [{"id": "1", "name": "Prod"}],
        "problemFilters": [{"id": "x", "name": "NOC"}],
    }
    problem.update(overrides)
    return problem


def test_api_closed_problem_is_resolved():
    alert = DynatraceProvider._format_alert(_api_problem())
    assert alert.status == AlertStatus.RESOLVED.value


def test_api_open_problem_is_firing():
    alert = DynatraceProvider._format_alert(_api_problem(status="OPEN"))
    assert alert.status == AlertStatus.FIRING.value


def test_api_problem_name_is_title_and_display_id_is_kept():
    alert = DynatraceProvider._format_alert(_api_problem())
    assert alert.name == "High Memory"
    assert alert.display_id == "P-2609315"
    assert alert.description == "P-2609315: High Memory | Affected: INFVPLAWS02 | Root cause: Windows System | Impact: INFRASTRUCTURE"


def test_api_problem_entities_are_flattened():
    alert = DynatraceProvider._format_alert(_api_problem())
    assert alert.service == "INFVPLAWS02"
    assert alert.affected_entity_names == "INFVPLAWS02"
    assert alert.root_cause == "Windows System"
    assert alert.management_zone_names == "Prod"
    assert alert.alerting_profiles == "NOC"


def test_api_problem_url_is_built_from_environment_id():
    from types import SimpleNamespace

    provider = SimpleNamespace(authentication_config=SimpleNamespace(environment_id="ysa24221"))
    alert = DynatraceProvider._format_alert(_api_problem(), provider)
    assert str(alert.url) == "https://ysa24221.apps.dynatrace.com/ui/apps/dynatrace.davis.problems/problem/-3061187654246811781_1758550140000V2"
    assert DynatraceProvider._format_alert(_api_problem(), None).url is None


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
    assert alert.severity == expected.value


def test_webhook_payload_still_maps():
    event = {
        "ProblemID": "-3061187654246811781_1758550140000V2",
        "ProblemTitle": "High Memory",
        "State": "RESOLVED",
        "ProblemSeverity": "RESOURCE_CONTENTION",
        "ProblemImpact": "INFRASTRUCTURE",
        "ProblemURL": "https://ysa24221.apps.dynatrace.com/ui/apps/dynatrace.classic.problems/#problems/problemdetails;pid=x",
        "ImpactedEntities": [{"type": "HOST", "name": "INFVPLAWS02", "entity": "HOST-1"}],
        "PID": "P-2609315",
        "Tags": "",
    }
    alert = DynatraceProvider._format_alert(event)
    assert alert.status == AlertStatus.RESOLVED.value
    assert alert.severity == AlertSeverity.WARNING.value
    assert alert.name == "High Memory"
    assert alert.service == "INFVPLAWS02"
    assert alert.description == "P-2609315: High Memory | Impacted: INFVPLAWS02 | Impact: INFRASTRUCTURE"
    assert str(alert.url).startswith("https://ysa24221.apps.dynatrace.com/")


def test_entity_tags_are_flattened_and_cloudfront_domain_promoted():
    problem = _api_problem(
        title="Cloudfront 4xx errors high",
        impactedEntities=[{"entityId": {"id": "CUSTOM_DEVICE-1", "type": "cloud:aws:cloud_front"}, "name": "E33H3ZCC3CRBVW"}],
        affectedEntities=[{"entityId": {"id": "CUSTOM_DEVICE-1", "type": "cloud:aws:cloud_front"}, "name": "E33H3ZCC3CRBVW"}],
        entityTags=[{"context": "CONTEXTLESS", "key": "AWSAcccount", "value": "allcam"}, {"context": "CONTEXTLESS", "key": "CloudfrontDomain", "value": "wild-match.com"}, {"context": "CONTEXTLESS", "key": "monitorEnable", "value": "true"}],
    )
    alert = DynatraceProvider._format_alert(problem)
    assert alert.entity_tags == {"AWSAcccount": "allcam", "CloudfrontDomain": "wild-match.com", "monitorEnable": "true"}
    assert alert.domain == "wild-match.com"
    assert alert.aws_account == "allcam"
    assert alert.cloudfront_distribution_id == "E33H3ZCC3CRBVW"


def test_webhook_tags_string_is_parsed():
    event = {"ProblemID": "x", "ProblemTitle": "t", "State": "OPEN", "ProblemSeverity": "CUSTOM_ALERT", "ImpactedEntities": [{"type": "CUSTOM_DEVICE", "name": "E33H3ZCC3CRBVW", "entity": "CUSTOM_DEVICE-1"}], "Tags": "[AWSAcccount:allcam, CloudfrontDomain:wild-match.com, monitorEnable]"}
    alert = DynatraceProvider._format_alert(event)
    assert alert.domain == "wild-match.com"
    assert alert.entity_tags["monitorEnable"] == "true"
    assert alert.cloudfront_distribution_id == "E33H3ZCC3CRBVW"
