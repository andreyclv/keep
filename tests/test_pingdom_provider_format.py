from keep.providers.pingdom_provider.pingdom_provider import PingdomProvider


def _event(**overrides):
    e = {
        "check_id": 41554, "check_name": "IML Wmaster response 2", "check_type": "HTTP", "current_state": "DOWN", "previous_state": "UP",
        "long_description": "HTTP Error 500", "description": "down", "importance_level": "HIGH", "time": 1758617253,
        "check_params": {"hostname": "imlive.com", "full_url": "http://imlive.com/wmaster.asp?cat=1", "port": 80, "url": "/wmaster.asp?cat=1"},
        "tags": [], "version": 1,
    }
    e.update(overrides)
    return e


def test_service_and_url_come_from_check_params():
    a = PingdomProvider._format_alert(_event())
    assert a.service == "imlive.com"
    assert a.hostname == "imlive.com"
    assert str(a.url) == "http://imlive.com/wmaster.asp?cat=1"
    assert a.fingerprint == "41554"
    assert a.status == "firing"


def test_up_resolves_and_missing_params_are_tolerated():
    a = PingdomProvider._format_alert(_event(current_state="UP", check_params={}))
    assert a.status == "resolved"
    assert a.service is None and a.url is None
