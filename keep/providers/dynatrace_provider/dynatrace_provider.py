"""
Kafka Provider is a class that allows to ingest/digest data from Grafana.
"""

import base64
import dataclasses
import datetime
import json
import logging
import os
from urllib.parse import quote

import pydantic
import requests

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.providers_factory import ProvidersFactory

logger = logging.getLogger(__name__)


@pydantic.dataclasses.dataclass
class DynatraceProviderAuthConfig:
    """
    Dynatrace authentication configuration.
    """

    environment_id: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Dynatrace's environment ID",
            "hint": "e.g. abcde",
        },
    )
    api_token: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Dynatrace's API token",
            "hint": "e.g. dt0c01.abcde...",
            "sensitive": True,
        },
    )
    alerting_profile: str = dataclasses.field(
        default="Default",
        metadata={
            "required": False,
            "description": "Dynatrace's alerting profile for the webhook integration. Defaults to 'Default'",
            "hint": "The name of the alerting profile to use for the webhook integration",
        },
    )


class DynatraceProvider(BaseProvider):
    """
    Dynatrace provider class.
    """

    PROVIDER_CATEGORY = ["Monitoring"]

    PROVIDER_SCOPES = [
        ProviderScope(
            name="problems.read",
            description="Read access to Dynatrace problems",
            mandatory=True,
            alias="Problem Read",
        ),
        ProviderScope(
            name="settings.read",
            description="Read access to Dynatrace settings [for webhook installation]",
            mandatory=False,
            alias="Settings Read",
        ),
        ProviderScope(
            name="settings.write",
            description="Write access to Dynatrace settings [for webhook installation]",
            mandatory=False,
            alias="Settings Write",
        ),
    ]
    FINGERPRINT_FIELDS = ["id"]

    # Problems API v2 severityLevel values plus the webhook {ProblemSeverity} placeholder values
    # https://docs.dynatrace.com/docs/dynatrace-api/environment-api/problems-v2/problems/get-problems-list
    SEVERITIES_MAP = {
        "AVAILABILITY": AlertSeverity.HIGH,
        "ERROR": AlertSeverity.CRITICAL,
        "PERFORMANCE": AlertSeverity.WARNING,
        "RESOURCE": AlertSeverity.WARNING,
        "RESOURCE_CONTENTION": AlertSeverity.WARNING,
        "MONITORING_UNAVAILABLE": AlertSeverity.WARNING,
        "CUSTOM": AlertSeverity.INFO,
        "CUSTOM_ALERT": AlertSeverity.INFO,
        "INFO": AlertSeverity.INFO,
    }

    # webhook {State} is OPEN / RESOLVED, Problems API v2 status is OPEN / CLOSED
    STATUS_MAP = {
        "OPEN": AlertStatus.FIRING,
        "RESOLVED": AlertStatus.RESOLVED,
        "CLOSED": AlertStatus.RESOLVED,
    }

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

    def _get_alerts(self) -> list[AlertDto]:
        """
        Get alerts from Dynatrace.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            list[AlertDto]: List of alerts.
        """
        self.logger.info("Getting alerts from Dynatrace")
        response = requests.get(
            f"https://{self.authentication_config.environment_id}.live.dynatrace.com/api/v2/problems",
            headers={
                "Authorization": f"Api-Token {self.authentication_config.api_token}"
            },
        )
        if not response.ok:
            self.logger.exception(
                f"Failed to get problems from Dynatrace: {response.text}"
            )
            raise Exception(f"Failed to get problems from Dynatrace: {response.text}")
        else:
            return [
                self._format_alert(event, provider_instance=self)
                for event in response.json().get("problems", [])
            ]

    def validate_scopes(self):
        self.logger.info("Validating dynatrace scopes")
        scopes = {}
        try:
            self._get_alerts()
        except Exception as e:
            # wrong environment
            if "Not Found" in str(e):
                self.logger.info(
                    "Failed to validate dynatrace scopes - wrong environment id"
                )
                scopes["problems.read"] = (
                    "Failed to validate scope, wrong environment id (Keep got 404)"
                )
                scopes["settings.read"] = scopes["problems.read"]
                scopes["settings.write"] = scopes["problems.read"]
                return scopes
            # authentication
            if "401" in str(e):
                self.logger.info(
                    "Failed to validate dynatrace scopes - invalid API token"
                )
                scopes["problems.read"] = (
                    "Invalid API token - authentication failed (401)"
                )
                scopes["settings.read"] = scopes["problems.read"]
                scopes["settings.write"] = scopes["problems.read"]
                return scopes
            if "403" in str(e):
                self.logger.info(
                    "Failed to validate dynatrace scopes - no problems.read scopes"
                )
                scopes["problems.read"] = (
                    "Token is missing required scope - problems.read (403)"
                )
        else:
            self.logger.info("Validated dynatrace scopes - problems.read")
            scopes["problems.read"] = True

        # check webhook scopes:
        # settings.read:
        try:
            self._get_alerting_profiles()
            self.logger.info("Validated dynatrace scopes - settings.read")
            scopes["settings.read"] = True
        except Exception as e:
            self.logger.info(
                f"Failed to validate dynatrace scopes - settings.read: {e}"
            )
            scopes["settings.read"] = str(e)
            scopes["settings.write"] = (
                "Cannot validate the settings.write scope without the settings.read scope, you need to first add the settings.read scope"
            )
            # we are done
            return scopes
        # if we have settings.read, we can try settings.write
        try:
            self.logger.info("Validating dynatrace scopes - settings.write")
            keep_api_url = os.environ.get("KEEP_API_URL")
            self.setup_webhook(
                tenant_id=self.context_manager.tenant_id,
                keep_api_url=keep_api_url,
                api_key="TEST",
                setup_alerts=False,
            )
            scopes["settings.write"] = True
            self.logger.info("Validated dynatrace scopes - settings.write")
        except Exception as e:
            self.logger.info(
                f"Failed to validate dynatrace scopes - settings.write: {e}"
            )
            # understand if its localhost:
            if "The environment does not allow for site-local URLs" in str(e):
                scopes["settings.write"] = (
                    "Cannot use localhost as a webhook URL, please use a public URL when installing dynatrace webhook (you can use Keep with ngrok or similar)"
                )
            else:
                scopes["settings.write"] = (
                    f"Failed to validate the settings.write scope: {e}"
                )
            return scopes

        self.logger.info(f"Validated dynatrace scopes: {scopes}")
        return scopes

    @staticmethod
    def _entity_names(entities) -> list[str]:
        """Names of Dynatrace entities from the Problems API / webhook (ImpactedEntities) shapes."""
        names = []
        for entity in entities or []:
            if isinstance(entity, dict):
                name = entity.get("name") or entity.get("entityName")
                if name:
                    names.append(str(name))
            elif isinstance(entity, str) and entity:
                names.append(entity)
        return names

    @staticmethod
    def _problem_url(provider_instance: "BaseProvider", problem_id: str) -> str | None:
        """Deep link to the problem in the Dynatrace UI (only the environment id is needed)."""
        authentication_config = getattr(provider_instance, "authentication_config", None)
        environment_id = getattr(authentication_config, "environment_id", None)
        if not environment_id or not problem_id:
            return None
        # Problems app deep link (no ';' matrix params: AlertDto percent-encodes them, which
        # would break the classic #problems/problemdetails;pid= form)
        return f"https://{environment_id}.apps.dynatrace.com/ui/apps/dynatrace.davis.problems/problem/{problem_id}"

    @staticmethod
    def _format_alert(
        event: dict, provider_instance: "BaseProvider" = None
    ) -> AlertDto:
        # alert that comes from webhook
        if event.get("ProblemID"):
            tags = event.get("Tags", [])
            impacted_entities = event.get("ImpactedEntities", [])
            problem_details_json = event.get("ProblemDetailsJSON", {})
            problem_details_jsonv2 = event.get("ProblemDetailsJSONv2", {})
            problem_details_text = event.get("ProblemDetailsText", "")
            impacted_entity_names = event.get("ImpactedEntityNames", [])
            impacted_entity = event.get("ImpactedEntity", "")
            pid = event.get("PID", "")
            names_of_impacted_entities = event.get("NamesOfImpactedEntities", "")
            event.get("ProblemDetails", "")
            # format severity and status to keep's format
            severity = DynatraceProvider.SEVERITIES_MAP.get(
                event.get("ProblemSeverity"), AlertSeverity.INFO
            )
            status = DynatraceProvider.STATUS_MAP.get(
                event.get("State"), AlertStatus.FIRING
            )
            url = event.get("ProblemURL")
            if url:
                try:
                    url = quote(url, safe=":/%#?=@&;+!")
                except Exception as e:
                    logger.exception(f"Failed to quote URL: {e}")
            entity_names = DynatraceProvider._entity_names(impacted_entities)
            if not entity_names and impacted_entity_names:
                entity_names = [
                    n.strip()
                    for n in str(impacted_entity_names).split(",")
                    if n.strip()
                ]
            description = f"{pid}: {event.get('ProblemTitle')}" if pid else event.get("ProblemTitle")
            if entity_names:
                description += f" | Impacted: {', '.join(entity_names)}"
            if event.get("ProblemImpact"):
                description += f" | Impact: {event.get('ProblemImpact')}"
            alert_dto = AlertDto(
                id=event.get("ProblemID"),
                name=event.get("ProblemTitle"),
                status=status,
                severity=severity,
                lastReceived=datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
                description=description,
                source=["dynatrace"],
                impact=event.get("ProblemImpact"),
                tags=tags,
                impactedEntities=impacted_entities,
                url=url,
                service=entity_names[0] if entity_names else None,
                display_id=pid or None,
                affected_entity_names=", ".join(entity_names) or None,
                problem_details_json=problem_details_json,
                problem_details_jsonv2=problem_details_jsonv2,
                problem_details_text=problem_details_text,
                impacted_entity_names=impacted_entity_names,
                impacted_entity=impacted_entity,
                pid=pid,
                names_of_impacted_entities=names_of_impacted_entities,
            )
        # else, problem from the problem API
        else:
            _id = event.pop("problemId")
            # keep the alert name consistent with the webhook path (problem title);
            # the human-readable display id (P-1234) is kept as a separate field
            display_id = event.pop("displayId")
            # format severity and status to keep's format
            severity = DynatraceProvider.SEVERITIES_MAP.get(
                event.pop("severityLevel", None), AlertSeverity.INFO
            )
            status = DynatraceProvider.STATUS_MAP.get(
                event.pop("status"), AlertStatus.FIRING
            )
            name = event.pop("title")
            impact = event.pop("impactLevel")
            tags = event.pop("entityTags")
            impacted_entities = event.pop("impactedEntities", [])
            affected_entities = event.get("affectedEntities", [])
            root_cause_entity = event.get("rootCauseEntity") or {}
            management_zones = DynatraceProvider._entity_names(event.get("managementZones"))
            alerting_profiles = DynatraceProvider._entity_names(event.get("problemFilters"))
            affected_names = DynatraceProvider._entity_names(affected_entities) or DynatraceProvider._entity_names(impacted_entities)
            root_cause_name = root_cause_entity.get("name") if isinstance(root_cause_entity, dict) else None
            description = f"{display_id}: {name}"
            if affected_names:
                description += f" | Affected: {', '.join(affected_names)}"
            if root_cause_name:
                description += f" | Root cause: {root_cause_name}"
            if impact:
                description += f" | Impact: {impact}"
            # the Problems API has no URL field; build the deep link from the environment id
            url = DynatraceProvider._problem_url(provider_instance, _id)
            lastReceived = datetime.datetime.fromtimestamp(
                event.pop("startTime") / 1000, tz=datetime.timezone.utc
            )
            alert_dto = AlertDto(
                id=_id,
                name=name,
                status=status,
                severity=severity,
                lastReceived=lastReceived.isoformat(),
                description=description,
                source=["dynatrace"],
                impact=impact,
                tags=tags,
                impactedEntities=impacted_entities,
                url=url,
                display_id=display_id,
                service=affected_names[0] if affected_names else None,
                affected_entity_names=", ".join(affected_names) or None,
                root_cause=root_cause_name,
                management_zone_names=", ".join(management_zones) or None,
                alerting_profiles=", ".join(alerting_profiles) or None,
                **event,  # any other field
            )
        alert_dto.fingerprint = DynatraceProvider.get_alert_fingerprint(
            alert_dto, DynatraceProvider.FINGERPRINT_FIELDS
        )
        return alert_dto

    def _get_alerting_profiles(self):
        self.logger.info("Getting alerting profiles")
        response = requests.get(
            f"https://{self.authentication_config.environment_id}.live.dynatrace.com/api/v2/settings/objects?schemaIds=builtin:alerting.profile",
            headers={
                "Authorization": f"Api-Token {self.authentication_config.api_token}"
            },
        )
        if response.ok:
            self.logger.info("Got alerting profiles")
            return response.json().get("items")
        elif "Use one of: settings.read" in response.text:
            self.logger.info(
                "Failed to get alerting profiles - missing settings.read scope"
            )
            raise Exception("Token is missing required scope - settings.read (403)")
        else:
            self.logger.info(
                f"Failed to get alerting profiles - {response.status_code} {response.text}"
            )
            raise Exception(
                f"Failed to get alerting profiles: {response.status_code} {response.text}"
            )

    def setup_webhook(
        self, tenant_id: str, keep_api_url: str, api_key: str, setup_alerts: bool = True
    ):
        """
        Setup Dynatrace webhook.

        Scope needed: environment (settings.write?)
        docs: https://docs.dynatrace.com/docs/dynatrace-api/environment-api/settings/schemas/builtin-problem-notifications#WebHookNotification
              https://docs.dynatrace.com/docs/dynatrace-api/environment-api/settings/objects/post-object
        """
        self.logger.info("Setting up Dynatrace webhook")
        # how to get it?
        alerting_profile_id = None
        alerting_profiles = self._get_alerting_profiles()
        for alerting_profile in alerting_profiles:
            if (
                alerting_profile.get("value").get("name")
                == self.authentication_config.alerting_profile
            ):
                alerting_profile_id = alerting_profile.get("objectId")
                self.logger.info(
                    f"Found alerting profile {self.authentication_config.alerting_profile} with id {alerting_profile_id}"
                )
                break

        if not alerting_profile_id:
            self.logger.info(
                f"Cannot find alerting profile {self.authentication_config.alerting_profile} in {alerting_profiles}"
            )
            raise Exception(
                f"Cannot find alerting profile {self.authentication_config.alerting_profile}"
            )

        auth_header = f"api_key:{api_key}"
        auth_header = base64.b64encode(auth_header.encode()).decode()
        payload = {
            "enabled": True,
            "displayName": f"Keep Webhook Integration - push alerts to Keep [tenant: {tenant_id}]",
            "type": "WEBHOOK",
            "alertingProfile": alerting_profile_id,
            "webHookNotification": {
                "acceptAnyCertificate": True,
                "headers": [
                    {
                        "name": "Authorization",
                        "secret": True,
                        "secretValue": f"Basic {auth_header}",
                    }
                ],
                "url": keep_api_url,
                "notifyClosedProblems": True,
                "notifyEventMergesEnabled": True,
                # all the fields - https://docs.dynatrace.com/docs/observe-and-explore/notifications-and-alerting/problem-notifications/webhook-integration#example-json-with-placeholders
                "payload": '{\n"State":"{State}",\n"ProblemID":"{ProblemID}",\n"ProblemTitle":"{ProblemTitle}",\n"ImpactedEntities": {ImpactedEntities},\n "PID": "{PID}",\n "ProblemDetailsJSON": {ProblemDetailsJSON},\n "ProblemImpact" : "{ProblemImpact}",\n"ProblemSeverity": "{ProblemSeverity}",\n "ProblemURL": "{ProblemURL}",\n"State": "{State}",\n"Tags": "{Tags}",\n"ProblemDetails": "{ProblemDetailsText}",\n"NamesOfImpactedEntities": "{NamesOfImpactedEntities}",\n"ImpactedEntity": "{ImpactedEntity}",\n"ImpactedEntityNames": "{ImpactedEntityNames}",\n"ProblemDetailsJSONv2": {ProblemDetailsJSONv2}\n}',
            },
        }
        actual_payload = [
            {
                "schemaId": "builtin:problem.notifications",
                "scope": "environment",
                "value": payload,
            }
        ]
        url = f"https://{self.authentication_config.environment_id}.live.dynatrace.com/api/v2/settings/objects"
        # if its a dry run to validate the scopes
        if not setup_alerts:
            url = f"https://{self.authentication_config.environment_id}.live.dynatrace.com/api/v2/settings/objects?validateOnly=true"

        # install the webhook
        response = requests.post(
            url,
            json=actual_payload,
            headers={
                "Authorization": f"Api-Token {self.authentication_config.api_token}"
            },
        )
        if not response.ok:
            # understand if its localhost:
            violation_message = (
                response.json()[0]
                .get("error")
                .get("constraintViolations")[0]
                .get("message")
            )
            if (
                violation_message
                == "The environment does not allow for site-local URLs"
            ):
                raise Exception(
                    "Dynatrace doesn't support use localhost as a webhook URL, use a public URL when installing dynatrace webhook."
                )
            else:
                raise Exception(
                    f"Failed to setup Dynatrace webhook: {response.status_code} {response.text}"
                )

    def dispose(self):
        """
        Dispose the provider.
        """
        pass

    def validate_config(self):
        """
        Validates required configuration for Dynatrace provider.

        """
        self.authentication_config = DynatraceProviderAuthConfig(
            **self.config.authentication
        )


if __name__ == "__main__":
    # Output debug messages
    import logging

    logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler()])

    # Load environment variables
    import os

    api_token = os.environ.get("DYNATRACE_API_TOKEN")
    environment_id = os.environ.get("DYNATRACE_ENVIRONMENT_ID")
    from keep.api.core.dependencies import SINGLE_TENANT_UUID

    context_manager = ContextManager(tenant_id=SINGLE_TENANT_UUID)
    config = {
        "authentication": {
            "api_token": api_token,
            "environment_id": environment_id,
        }
    }
    provider = ProvidersFactory.get_provider(
        context_manager,
        provider_id="dynatrace-keephq",
        provider_type="dynatrace",
        provider_config=config,
    )
    problems = provider._get_alerts()
    provider.setup_webhook(
        tenant_id=SINGLE_TENANT_UUID,
        keep_api_url=os.environ.get("KEEP_API_URL"),
        api_key=context_manager.api_key,
        setup_alerts=True,
    )
