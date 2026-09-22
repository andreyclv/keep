"""
Zabbix renders {DATE} {TIME} in the webhook payload in the Zabbix server's local
timezone without an offset. The provider must interpret it in the configured
timezone so lastReceived is correct in UTC.
"""

import datetime
from types import SimpleNamespace

import pytest

from keep.providers.zabbix_provider.zabbix_provider import ZabbixProvider


def _event(**overrides):
    event = {
        "id": "29373570",
        "name": "Number of installed packages has been changed",
        "severity": "Warning",
        "status": "PROBLEM",
        "lastReceived": "2026.09.22 13:53:43",
        "service": "CLVTESTFLOW01",
        "tags": "[]",
    }
    event.update(overrides)
    return event


def _provider(timezone):
    return SimpleNamespace(authentication_config=SimpleNamespace(timezone=timezone))


def test_last_received_defaults_to_utc_without_provider_instance():
    alert = ZabbixProvider._format_alert(_event(), None)
    assert alert.lastReceived == "2026-09-22T13:53:43+00:00"


def test_last_received_uses_configured_timezone():
    alert = ZabbixProvider._format_alert(_event(), _provider("Asia/Jerusalem"))
    # 13:53:43 in Jerusalem (UTC+3 in September) is 10:53:43 UTC
    parsed = datetime.datetime.fromisoformat(alert.lastReceived)
    assert parsed.utcoffset() == datetime.timedelta(hours=3)
    assert parsed.astimezone(datetime.timezone.utc).isoformat() == "2026-09-22T10:53:43+00:00"


@pytest.mark.parametrize("timezone", [None, "", "Not/AZone"])
def test_last_received_falls_back_to_utc_on_bad_timezone(timezone):
    alert = ZabbixProvider._format_alert(_event(), _provider(timezone))
    assert alert.lastReceived == "2026-09-22T13:53:43+00:00"


def test_test_message_placeholder_is_replaced_with_now():
    alert = ZabbixProvider._format_alert(_event(lastReceived="{DATE} {TIME}"), _provider("Asia/Jerusalem"))
    parsed = datetime.datetime.fromisoformat(alert.lastReceived)
    assert abs((datetime.datetime.now(tz=datetime.timezone.utc) - parsed).total_seconds()) < 60
