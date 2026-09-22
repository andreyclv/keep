"""
OpenSearch enrichment provider: profile parsing, entity parsing, query building and normalization.
Network is mocked at the provider's _request boundary.
"""

import json
from unittest.mock import patch

import pytest

from keep.contextmanager.contextmanager import ContextManager
from keep.providers.models.provider_config import ProviderConfig
from keep.providers.opensearch_provider.opensearch_provider import OpensearchProvider

PROFILES = """
search_profiles:
  defaults: {time_field: timestamp, lookback: 15m, size: 5}
  families:
    - name: app-logs
      patterns: [inf-app-*, il2-app-*]
      match_fields:
        hostname: ["object.keyword:*/mnt/log_mounts/{value}/*"]
      error: {field: severity.keyword, values: [Error]}
      warning: {field: severity.keyword, values: [Warning]}
      message_field: logMessage
      extra_fields: [method]
    - name: iis
      patterns: [il2-iis-*]
      match_fields:
        hostname: [sComputerName.keyword]
        domain: [csHost.keyword]
        url: [{domain: csHost.keyword, path: csUri.keyword}]
      error: {field: csStatus.keyword, min: 500}
      warning: {field: csStatus.keyword, min: 400, max: 499}
      message_field: csUri
      extra_fields: [csStatus, timeTaken]
    - name: windows-events
      patterns: [winlogbeat-*]
      time_field: "@timestamp"
      match_fields:
        hostname: ["host.name:{value}*"]
      error: {field: log.level, values: [error]}
      message_field: message
    - name: pipeline-dropped
      patterns: [vector-dropped-*]
      match_fields:
        hostname: ["object.keyword:*/mnt/log_mounts/{value}/*"]
      error: {field: metadata.dropped.reason.keyword, values_not: []}
      message_field: metadata.dropped.reason
"""


def _provider(profiles=PROFILES):
    ctx = ContextManager(tenant_id="keep", workflow_id="test")
    config = ProviderConfig(
        description="test",
        authentication={
            "host": "https://os.example.com",
            "username": "keephq",
            "password": "x",
            "dashboards_url": "https://logs.example.com/_dashboards",
            "search_profiles": profiles,
        },
    )
    return OpensearchProvider(ctx, "opensearch", config)


def test_profiles_parse_from_yaml_text():
    p = _provider()
    assert [f["name"] for f in p.profiles["families"]] == ["app-logs", "iis", "windows-events", "pipeline-dropped"]
    assert p.profiles["defaults"]["lookback"] == "15m"


def test_profiles_accept_dict():
    p = _provider({"families": [{"name": "x", "patterns": ["x-*"]}]})
    assert p.profiles["families"][0]["patterns"] == ["x-*"]
    assert p.profiles["defaults"]["time_field"] == "@timestamp"


@pytest.mark.parametrize(
    "entity_type,value,expected",
    [
        ("hostname", "IL2WEBAWS05.lan.coolvision.biz", {"value": "IL2WEBAWS05.lan.coolvision.biz", "short": "IL2WEBAWS05"}),
        ("domain", "https://M.IMLIVE.com/x", {"value": "m.imlive.com"}),
        ("url", "https://m.imlive.com/MobileTemplateV2.aspx?p=1", {"value": "https://m.imlive.com/MobileTemplateV2.aspx?p=1", "domain": "m.imlive.com", "path": "/MobileTemplateV2.aspx"}),
        ("url", "/health", {"value": "/health", "domain": None, "path": "/health"}),
    ],
)
def test_parse_entity(entity_type, value, expected):
    assert OpensearchProvider.parse_entity(entity_type, value) == expected


def test_entity_filter_shapes():
    p = _provider()
    fams = {f["name"]: f for f in p.profiles["families"]}
    host = p.parse_entity("hostname", "INFAPPAWS03.lan")
    wildcard = p._entity_filter(fams["app-logs"], "hostname", host)
    assert wildcard == {"bool": {"should": [{"wildcard": {"object.keyword": {"value": "*/mnt/log_mounts/INFAPPAWS03/*", "case_insensitive": True}}}], "minimum_should_match": 1}}
    term = p._entity_filter(fams["iis"], "hostname", host)
    assert term["bool"]["should"][0] == {"term": {"sComputerName.keyword": {"value": "INFAPPAWS03", "case_insensitive": True}}}
    assert p._entity_filter(fams["app-logs"], "domain", p.parse_entity("domain", "x.com")) is None
    url = p._entity_filter(fams["iis"], "url", p.parse_entity("url", "https://m.imlive.com/a.aspx"))
    filters = url["bool"]["should"][0]["bool"]["filter"]
    assert filters[0] == {"term": {"csHost.keyword": {"value": "m.imlive.com", "case_insensitive": True}}}
    assert filters[1] == {"term": {"csUri.keyword": {"value": "/a.aspx", "case_insensitive": True}}}
    path_only = p._entity_filter(fams["iis"], "url", p.parse_entity("url", "/a.aspx"))
    assert len(path_only["bool"]["should"][0]["bool"]["filter"]) == 1


def test_level_clauses():
    assert OpensearchProvider._level_clause({"field": "severity.keyword", "values": ["Error"]}) == {"terms": {"severity.keyword": ["Error"]}}
    assert OpensearchProvider._level_clause({"field": "csStatus.keyword", "min": 500}) == {"range": {"csStatus.keyword": {"gte": "500"}}}
    assert OpensearchProvider._level_clause({"field": "code", "min": 400, "max": 499}) == {"range": {"code": {"gte": 400, "lte": 499}}}
    assert OpensearchProvider._level_clause({"field": "x", "values_not": []}) == {"match_all": {}}
    assert OpensearchProvider._level_clause(None) is None


def test_build_search_uses_family_time_field_and_post_filter():
    p = _provider()
    fam = [f for f in p.profiles["families"] if f["name"] == "windows-events"][0]
    search = p._build_search(fam, {"match_all": {}}, "1h", 3)
    assert search["query"]["bool"]["filter"][0] == {"range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}}
    assert search["post_filter"] == {"terms": {"log.level": ["error"]}}
    assert search["aggs"]["errors"]["aggs"]["top_messages"]["terms"]["field"] == "message.keyword"
    assert search["size"] == 3


def _msearch_response():
    return {
        "responses": [
            {  # app-logs
                "hits": {"total": {"value": 32003}, "hits": [
                    {"_index": "inf-app-2026-09-22", "_source": {"timestamp": "2026-09-22T16:52:02Z", "logMessage": "Timeout calling X", "method": "Cmd_A"}},
                ]},
                "aggregations": {
                    "by_index": {"buckets": [{"key": "inf-app-2026-09-22", "doc_count": 32003}]},
                    "errors": {"doc_count": 101, "top_messages": {"buckets": [{"key": "Timeout calling X", "doc_count": 90}]}},
                    "warnings": {"doc_count": 5845},
                },
            },
            {  # iis
                "hits": {"total": {"value": 1200}, "hits": [
                    {"_index": "il2-iis-2026-09-22", "_source": {"timestamp": "2026-09-22T16:55:00Z", "csUri": "/x.aspx", "csStatus": "500", "timeTaken": "10"}},
                ]},
                "aggregations": {
                    "by_index": {"buckets": [{"key": "il2-iis-2026-09-22", "doc_count": 1200}]},
                    "errors": {"doc_count": 7, "top_messages": {"buckets": [{"key": "/x.aspx", "doc_count": 7}]}},
                    "warnings": {"doc_count": 40},
                },
            },
            {"error": {"reason": "no such index [winlogbeat-*]"}},  # windows-events
            {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {"by_index": {"buckets": []}, "errors": {"doc_count": 0}}},  # pipeline-dropped
        ]
    }


def test_query_hostname_normalizes_across_families():
    p = _provider()
    sent = {}

    def fake_request(method, path, body=None, ndjson=None, timeout=60):
        sent["method"], sent["path"], sent["ndjson"] = method, path, ndjson
        return _msearch_response()

    with patch.object(OpensearchProvider, "_request", side_effect=fake_request):
        result = p._query(entity_type="hostname", value="INFAPPAWS03", lookback="30m")

    assert sent["path"] == "_msearch"
    lines = [json.loads(line) for line in sent["ndjson"].strip().split("\n")]
    assert lines[0] == {"index": ["inf-app-*", "il2-app-*"], "ignore_unavailable": True}
    assert len(lines) == 8  # 4 families x (header + body)
    assert result["total_docs"] == 33203
    assert result["total_errors"] == 108
    assert result["total_warnings"] == 5885
    assert result["families_searched"] == ["app-logs", "iis", "windows-events", "pipeline-dropped"]
    assert [f["family"] for f in result["by_family"] if f.get("error")] == ["windows-events"]
    assert result["top_messages"][0] == {"message": "Timeout calling X", "count": 90, "family": "app-logs"}
    assert result["samples"][0]["index"] == "il2-iis-2026-09-22"
    assert result["samples"][0]["extra"] == {"csStatus": "500", "timeTaken": "10"}
    assert result["samples"][1]["message"] == "Timeout calling X"
    assert result["dashboards_url"].startswith("https://logs.example.com/_dashboards/app/data-explorer/discover#?_g=(time:(from:now-30m,to:now))")


def test_query_domain_only_hits_families_that_know_domains():
    p = _provider()
    with patch.object(OpensearchProvider, "_request", return_value={"responses": [{"hits": {"total": {"value": 3}, "hits": []}, "aggregations": {"by_index": {"buckets": []}, "errors": {"doc_count": 1}}}]}) as req:
        result = p._query(entity_type="domain", value="m.imlive.com")
    lines = [json.loads(line) for line in req.call_args.kwargs["ndjson"].strip().split("\n")]
    assert lines[0]["index"] == ["il2-iis-*"]
    assert result["families_searched"] == ["iis"]
    assert result["total_errors"] == 1


def test_query_rejects_bad_input():
    p = _provider()
    with pytest.raises(Exception):
        p._query(entity_type="container", value="x")
    with pytest.raises(Exception):
        p._query(entity_type="hostname", value="x", lookback="soon")


def test_raw_search_passthrough():
    p = _provider()
    with patch.object(OpensearchProvider, "_request", return_value={"hits": {"total": {"value": 1}}}) as req:
        out = p._query(index="inf-app-*", body={"size": 0})
    assert out == {"hits": {"total": {"value": 1}}}
    assert req.call_args.args[:2] == ("POST", "inf-app-*/_search")


def test_validate_profiles_reports_missing_fields_and_patterns():
    p = _provider()

    def fake_request(method, path, body=None, ndjson=None, timeout=60):
        assert "_field_caps" in path
        if path.startswith("winlogbeat"):
            return {"indices": [], "fields": {}}
        return {"indices": ["x"], "fields": {"timestamp": {}, "object.keyword": {}, "severity.keyword": {}, "logMessage": {}, "method": {}, "sComputerName.keyword": {}, "csHost.keyword": {}, "csUri.keyword": {}, "csStatus.keyword": {}, "csUri": {}, "csStatus": {}, "metadata.dropped.reason.keyword": {}, "metadata.dropped.reason": {}}}

    with patch.object(OpensearchProvider, "_request", side_effect=fake_request):
        problems = p.validate_profiles()
    assert any(pr.startswith("windows-events: no index matches") for pr in problems)
    assert any(pr.startswith("iis: unknown fields timeTaken") for pr in problems)
    assert not any(pr.startswith("app-logs") for pr in problems)
