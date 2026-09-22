"""
OpenSearch provider: enrich alerts with what the logs say about a host, a domain or a URL.

The provider does not ingest alerts. It holds "search profiles" that describe, per log family, which index
patterns to search, how to match an entity (hostname / domain / url) despite differing field names, what
counts as an error, and which fields to return. A workflow step calls `query` with an entity and gets a
normalized summary back regardless of which indices answered.
"""

import dataclasses
import datetime
import json
import re
import typing
from urllib.parse import quote, urlparse

import pydantic
import requests
import yaml

from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_exception import ProviderException
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope

ENTITY_TYPES = ("hostname", "domain", "url")
LOOKBACK_RE = re.compile(r"^\d+[smhd]$")


@pydantic.dataclasses.dataclass
class OpensearchProviderAuthConfig:
    """OpenSearch authentication and search profiles."""

    host: pydantic.AnyHttpUrl = dataclasses.field(
        metadata={
            "required": True,
            "description": "OpenSearch endpoint",
            "hint": "https://vpc-xxx.us-east-1.es.amazonaws.com or https://opensearch.example.com:9200",
            "validation": "any_http_url",
        }
    )
    username: str = dataclasses.field(
        default=None,
        metadata={
            "required": False,
            "description": "Username (fine-grained access control / security plugin internal user)",
            "sensitive": False,
        },
    )
    password: str = dataclasses.field(
        default=None,
        metadata={
            "required": False,
            "description": "Password",
            "sensitive": True,
        },
    )
    verify: bool = dataclasses.field(
        default=True,
        metadata={
            "required": False,
            "description": "Verify TLS certificates",
            "hint": "Set to false for self-signed certificates",
            "sensitive": False,
        },
    )
    dashboards_url: str = dataclasses.field(
        default=None,
        metadata={
            "required": False,
            "description": "OpenSearch Dashboards base URL, used to build links into Discover",
            "hint": "https://logs.example.com/_dashboards",
            "sensitive": False,
        },
    )
    search_profiles: typing.Union[str, dict] = dataclasses.field(
        default=None,
        metadata={
            "required": False,
            "description": "Search profiles (YAML or JSON): per log family, the index patterns, how to match a hostname/domain/url, what an error is and which fields to return",
            "hint": "See the provider documentation for the schema",
            "sensitive": False,
        },
    )


class OpensearchProvider(BaseProvider):
    """Enrich alerts with data from OpenSearch."""

    PROVIDER_DISPLAY_NAME = "OpenSearch"
    PROVIDER_CATEGORY = ["Monitoring", "Database"]
    PROVIDER_TAGS = []

    PROVIDER_SCOPES = [
        ProviderScope(
            name="connect_to_server",
            description="Can reach the cluster (cluster health)",
            mandatory=True,
            alias="Connect to the server",
        ),
        ProviderScope(
            name="search_profiles",
            description="Every index pattern in the search profiles resolves and the configured fields exist",
            mandatory=False,
            alias="Search profiles are valid",
        ),
    ]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
        self._session = None
        self._profiles = None

    # ------------------------------------------------------------------ config

    def validate_config(self):
        self.authentication_config = OpensearchProviderAuthConfig(
            **self.config.authentication
        )

    def dispose(self):
        if self._session:
            self._session.close()
            self._session = None

    @property
    def profiles(self) -> dict:
        if self._profiles is None:
            self._profiles = self.parse_profiles(self.authentication_config.search_profiles)
        return self._profiles

    @staticmethod
    def parse_profiles(raw) -> dict:
        """Accept YAML/JSON text or a dict; return {"defaults": {...}, "families": [...]}."""
        if not raw:
            return {"defaults": {}, "families": []}
        if isinstance(raw, str):
            raw = yaml.safe_load(raw)
        if not isinstance(raw, dict):
            raise ProviderException("search_profiles must be a mapping")
        # allow either the bare document or one nested under 'search_profiles'
        if "search_profiles" in raw and isinstance(raw["search_profiles"], dict):
            raw = raw["search_profiles"]
        defaults = {"time_field": "@timestamp", "lookback": "15m", "size": 10}
        defaults.update(raw.get("defaults") or {})
        families = []
        for fam in raw.get("families") or []:
            if not fam.get("name") or not fam.get("patterns"):
                raise ProviderException("every family needs a name and patterns")
            families.append(fam)
        return {"defaults": defaults, "families": families}

    # ------------------------------------------------------------------ http

    @property
    def session(self) -> requests.Session:
        if self._session is None:
            s = requests.Session()
            if self.authentication_config.username:
                s.auth = (
                    self.authentication_config.username,
                    self.authentication_config.password or "",
                )
            s.verify = self.authentication_config.verify
            s.headers["Content-Type"] = "application/json"
            self._session = s
        return self._session

    def _request(self, method: str, path: str, body=None, ndjson: str = None, timeout: int = 60):
        url = str(self.authentication_config.host).rstrip("/") + "/" + path.lstrip("/")
        kwargs = {"timeout": timeout}
        if ndjson is not None:
            kwargs["data"] = ndjson
            kwargs["headers"] = {"Content-Type": "application/x-ndjson"}
        elif body is not None:
            kwargs["data"] = json.dumps(body)
        resp = self.session.request(method, url, **kwargs)
        if resp.status_code >= 400:
            raise ProviderException(
                f"OpenSearch {method} {path} failed: {resp.status_code} {resp.text[:300]}"
            )
        return resp.json() if resp.text else {}

    # ------------------------------------------------------------------ scopes

    def validate_scopes(self) -> dict[str, bool | str]:
        scopes = {}
        try:
            health = self._request("GET", "_cluster/health")
            scopes["connect_to_server"] = True
            self.logger.info("OpenSearch reachable", extra={"status": health.get("status")})
        except Exception as e:
            scopes["connect_to_server"] = str(e)
            scopes["search_profiles"] = "Cannot validate profiles without a connection"
            return scopes
        try:
            problems = self.validate_profiles()
            scopes["search_profiles"] = True if not problems else "; ".join(problems)[:1000]
        except Exception as e:
            scopes["search_profiles"] = str(e)
        return scopes

    def validate_profiles(self) -> list[str]:
        """
        Check every family: the patterns match at least one index and the configured fields exist.
        Uses only _field_caps (covered by the 'read' action group), so a read-only user suffices.
        """
        problems = []
        if not self.profiles["families"]:
            return ["no search profiles configured"]
        for fam in self.profiles["families"]:
            patterns = ",".join(fam["patterns"])
            wanted = set(self._fields_used(fam))
            fields_param = ",".join(sorted(wanted)) if wanted else "*"
            try:
                caps = self._request(
                    "GET",
                    f"{quote(patterns, safe='*,-_')}/_field_caps?fields={quote(fields_param, safe=',.*')}&ignore_unavailable=true&allow_no_indices=true",
                )
            except Exception as e:
                problems.append(f"{fam['name']}: field_caps on {patterns} failed ({e})")
                continue
            if not caps.get("indices"):
                problems.append(f"{fam['name']}: no index matches {patterns}")
                continue
            missing = sorted(f for f in wanted if f not in (caps.get("fields") or {}))
            if missing:
                problems.append(f"{fam['name']}: unknown fields {', '.join(missing)}")
        return problems

    def _fields_used(self, fam: dict) -> list[str]:
        fields = [self._time_field(fam)]
        for spec_list in (fam.get("match_fields") or {}).values():
            for spec in self._as_list(spec_list):
                if isinstance(spec, dict):
                    fields.extend(v.split(":", 1)[0] for v in spec.values() if v)
                else:
                    fields.append(str(spec).split(":", 1)[0])
        for key in ("error", "warning"):
            spec = fam.get(key)
            if isinstance(spec, dict) and spec.get("field"):
                fields.append(spec["field"])
        if fam.get("message_field"):
            fields.append(fam["message_field"])
        fields.extend(fam.get("extra_fields") or [])
        return [f for f in fields if f]

    # ------------------------------------------------------------------ query

    def _query(
        self,
        entity_type: str = None,
        value: str = None,
        lookback: str = None,
        size: int = None,
        families: typing.Union[str, list] = None,
        index: str = None,
        body: dict = None,
        **kwargs,
    ) -> dict:
        """
        Two modes:
        - profile search: entity_type (hostname | domain | url) + value, optional lookback (e.g. 15m), size,
          families (subset of family names). Returns a normalized summary.
        - raw search: index + body, returns the OpenSearch response as-is.
        """
        if index and body is not None:
            if isinstance(body, str):
                body = json.loads(body)
            return self._request("POST", f"{quote(index, safe='*,-_')}/_search", body=body)
        if not entity_type or not value:
            raise ProviderException("query needs entity_type and value (or index and body for a raw search)")
        entity_type = str(entity_type).lower()
        if entity_type not in ENTITY_TYPES:
            raise ProviderException(f"entity_type must be one of {ENTITY_TYPES}")
        defaults = self.profiles["defaults"]
        lookback = str(lookback or defaults["lookback"])
        if not LOOKBACK_RE.match(lookback):
            raise ProviderException("lookback must look like 15m, 2h or 1d")
        size = int(size or defaults["size"])
        wanted = set(self._as_list(families)) if families else None

        entity = self.parse_entity(entity_type, value)
        searches = []
        for fam in self.profiles["families"]:
            if wanted and fam["name"] not in wanted:
                continue
            match_filter = self._entity_filter(fam, entity_type, entity)
            if match_filter is None:
                continue
            searches.append((fam, self._build_search(fam, match_filter, lookback, size)))
        if not searches:
            return self._empty_result(entity_type, value, lookback, "no family matches this entity type")

        ndjson = ""
        for fam, search in searches:
            ndjson += json.dumps({"index": fam["patterns"], "ignore_unavailable": True}) + "\n"
            ndjson += json.dumps(search) + "\n"
        response = self._request("POST", "_msearch", ndjson=ndjson, timeout=120)
        return self._normalize(entity_type, value, entity, lookback, size, searches, response)

    # ---- entity handling

    @staticmethod
    def parse_entity(entity_type: str, value: str) -> dict:
        """Break the raw value into the parts profiles match on."""
        value = str(value).strip()
        if entity_type == "hostname":
            short = value.split(".")[0]
            return {"value": value, "short": short}
        if entity_type == "domain":
            v = value.lower()
            if "://" in v:
                v = urlparse(v).hostname or v
            return {"value": v}
        # url: full URL, host+path, or bare path
        v = value if "://" in value else ("//" + value if not value.startswith("/") else value)
        parsed = urlparse(v)
        return {
            "value": value,
            "domain": (parsed.hostname or "").lower() or None,
            "path": parsed.path or None,
        }

    @staticmethod
    def _as_list(spec) -> list:
        if spec is None:
            return []
        if isinstance(spec, (list, tuple)):
            return list(spec)
        return [spec]

    @staticmethod
    def _field_clause(spec: str, value: str) -> dict:
        """
        "field"                  -> case-insensitive term
        "field:pattern{value}"   -> case-insensitive wildcard, {value} substituted
        """
        if ":" in spec:
            field, pattern = spec.split(":", 1)
            return {
                "wildcard": {
                    field: {"value": pattern.replace("{value}", value), "case_insensitive": True}
                }
            }
        return {"term": {spec: {"value": value, "case_insensitive": True}}}

    def _entity_filter(self, fam: dict, entity_type: str, entity: dict):
        specs = (fam.get("match_fields") or {}).get(entity_type)
        if not specs:
            return None
        if entity_type == "url":
            # one dict spec: {domain: field, path: field}; either part may be absent in the value
            clauses = []
            for spec in self._as_list(specs):
                if not isinstance(spec, dict):
                    continue
                must = []
                if entity.get("domain") and spec.get("domain"):
                    must.append(self._field_clause(spec["domain"], entity["domain"]))
                if entity.get("path") and spec.get("path"):
                    must.append(self._field_clause(spec["path"], entity["path"]))
                if must:
                    clauses.append({"bool": {"filter": must}})
            if not clauses:
                return None
            return {"bool": {"should": clauses, "minimum_should_match": 1}}
        value = entity["short"] if entity_type == "hostname" else entity["value"]
        clauses = [self._field_clause(str(spec), value) for spec in self._as_list(specs)]
        return {"bool": {"should": clauses, "minimum_should_match": 1}}

    # ---- search building

    def _time_field(self, fam: dict) -> str:
        return fam.get("time_field") or self.profiles["defaults"]["time_field"]

    @staticmethod
    def _level_clause(spec) -> typing.Optional[dict]:
        """error / warning spec -> query clause, or None when the family has no such concept."""
        if not spec or not isinstance(spec, dict):
            return None
        field = spec.get("field")
        if "values_not" in spec:
            excluded = spec.get("values_not") or []
            if not excluded:
                return {"match_all": {}}
            return {"bool": {"must_not": [{"terms": {field: excluded}}]}}
        if spec.get("values"):
            return {"terms": {field: spec["values"]}}
        if "min" in spec or "max" in spec:
            rng = {}
            if "min" in spec:
                rng["gte"] = str(spec["min"]) if field.endswith(".keyword") else spec["min"]
            if "max" in spec:
                rng["lte"] = str(spec["max"]) if field.endswith(".keyword") else spec["max"]
            return {"range": {field: rng}}
        return None

    def _build_search(self, fam: dict, match_filter: dict, lookback: str, size: int) -> dict:
        time_field = self._time_field(fam)
        message_field = fam.get("message_field")
        error_clause = self._level_clause(fam.get("error"))
        warning_clause = self._level_clause(fam.get("warning"))
        aggs = {"by_index": {"terms": {"field": "_index", "size": 50}}}
        if error_clause:
            error_aggs = {}
            if message_field:
                error_aggs["top_messages"] = {
                    "terms": {"field": self._keyword(message_field), "size": 5}
                }
            aggs["errors"] = {"filter": error_clause, "aggs": error_aggs}
        if warning_clause:
            aggs["warnings"] = {"filter": warning_clause}
        source_fields = [time_field] + ([message_field] if message_field else []) + list(fam.get("extra_fields") or [])
        search = {
            "size": size,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {time_field: {"gte": f"now-{lookback}", "lte": "now"}}},
                        match_filter,
                    ]
                }
            },
            "sort": [{time_field: {"order": "desc", "unmapped_type": "date"}}],
            "_source": source_fields,
            "aggs": aggs,
        }
        # samples should be the errors when the family knows what an error is
        if error_clause:
            search["post_filter"] = error_clause
        return search

    @staticmethod
    def _keyword(field: str) -> str:
        return field if field.endswith(".keyword") else f"{field}.keyword"

    # ---- normalization

    def _empty_result(self, entity_type, value, lookback, note) -> dict:
        return {
            "entity_type": entity_type,
            "value": value,
            "lookback": lookback,
            "total_docs": 0,
            "total_errors": 0,
            "total_warnings": 0,
            "by_family": [],
            "by_index": [],
            "top_messages": [],
            "samples": [],
            "families_searched": [],
            "note": note,
            "dashboards_url": None,
        }

    def _normalize(self, entity_type, value, entity, lookback, size, searches, response) -> dict:
        result = self._empty_result(entity_type, value, lookback, None)
        del result["note"]
        responses = response.get("responses") or []
        for (fam, search), resp in zip(searches, responses):
            family = {"family": fam["name"], "patterns": fam["patterns"], "docs": 0, "errors": 0, "warnings": 0, "indices": []}
            result["families_searched"].append(fam["name"])
            if "error" in resp:
                family["error"] = str(resp["error"].get("reason") or resp["error"])[:200]
                result["by_family"].append(family)
                continue
            total = resp.get("hits", {}).get("total", {})
            family["docs"] = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
            aggs = resp.get("aggregations") or {}
            for b in aggs.get("by_index", {}).get("buckets", []):
                family["indices"].append(b["key"])
                result["by_index"].append({"index": b["key"], "family": fam["name"], "docs": b["doc_count"]})
            has_error_concept = "errors" in aggs
            if has_error_concept:
                family["errors"] = aggs["errors"].get("doc_count", 0)
                for b in aggs["errors"].get("top_messages", {}).get("buckets", []):
                    result["top_messages"].append({"message": b["key"], "count": b["doc_count"], "family": fam["name"]})
            if "warnings" in aggs:
                family["warnings"] = aggs["warnings"].get("doc_count", 0)
            time_field = self._time_field(fam)
            for hit in resp.get("hits", {}).get("hits", []):
                src = hit.get("_source") or {}
                sample = {
                    "timestamp": self._dig(src, time_field),
                    "index": hit.get("_index"),
                    "family": fam["name"],
                    "message": self._dig(src, fam.get("message_field")) if fam.get("message_field") else None,
                    "is_error": has_error_concept,
                }
                extra = {f: self._dig(src, f) for f in (fam.get("extra_fields") or [])}
                sample["extra"] = {k: v for k, v in extra.items() if v is not None}
                result["samples"].append(sample)
            result["total_docs"] += family["docs"]
            result["total_errors"] += family["errors"]
            result["total_warnings"] += family["warnings"]
            result["by_family"].append(family)
        result["top_messages"].sort(key=lambda m: -m["count"])
        result["top_messages"] = result["top_messages"][:10]
        result["samples"].sort(key=lambda s: str(s.get("timestamp") or ""), reverse=True)
        result["samples"] = result["samples"][:size]
        result["dashboards_url"] = self._dashboards_link(entity_type, entity, lookback)
        return result

    @staticmethod
    def _dig(doc: dict, path: str):
        if not path:
            return None
        if path in doc:
            return doc[path]
        cur = doc
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur

    def _dashboards_link(self, entity_type, entity, lookback) -> typing.Optional[str]:
        base = self.authentication_config.dashboards_url
        if not base:
            return None
        if entity_type == "hostname":
            kql = f'"{entity["short"]}"'
        elif entity_type == "domain":
            kql = f'"{entity["value"]}"'
        else:
            kql = " and ".join(f'"{p}"' for p in (entity.get("domain"), entity.get("path")) if p) or f'"{entity["value"]}"'
        query = quote(f"(query:(language:kuery,query:'{kql}'))", safe="(),:'")
        time = f"(time:(from:now-{lookback},to:now))"
        return f"{base.rstrip('/')}/app/data-explorer/discover#?_g={time}&_q={query}"


if __name__ == "__main__":
    import logging
    import os

    logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler()])
    from keep.api.core.dependencies import SINGLE_TENANT_UUID
    from keep.providers.providers_factory import ProvidersFactory

    context_manager = ContextManager(tenant_id=SINGLE_TENANT_UUID, workflow_id="test")
    config = {
        "authentication": {
            "host": os.environ["OPENSEARCH_HOST"],
            "username": os.environ.get("OPENSEARCH_USER"),
            "password": os.environ.get("OPENSEARCH_PASSWORD"),
            "search_profiles": open(os.environ["OPENSEARCH_PROFILES"]).read(),
        }
    }
    provider = ProvidersFactory.get_provider(
        context_manager, provider_id="opensearch", provider_type="opensearch", provider_config=config
    )
    print(json.dumps(provider.validate_scopes(), indent=2))
    print(json.dumps(provider.query(entity_type="hostname", value=os.environ.get("ENTITY", "INFAPPAWS03")), indent=2, default=str))
