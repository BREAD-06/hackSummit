"""Unit tests for the enterprise Policy Engine and SOC Policy Center integration."""

import pytest
from server.db.sqlite_store import SQLiteStorage
from server.policy.engine import (
    PolicyConfig,
    PolicyEngine,
    USB_ALERT,
    USB_ALLOWED,
    USB_BLOCKED,
    USB_DISABLED,
    AFTER_HOURS_ALERT,
    AFTER_HOURS_DISABLED,
)


@pytest.fixture
def storage(tmp_path):
    store = SQLiteStorage(str(tmp_path / "test_policy.db"))
    store.init_schema()
    return store


def test_policy_engine_defaults(storage):
    engine = PolicyEngine(storage)
    policy = engine.get_policy()

    assert policy["threat_rules"]["usb_policy"] == USB_ALERT
    assert policy["threat_rules"]["after_hours_policy"] == AFTER_HOURS_ALERT
    assert policy["response_actions"]["auto_containment"] is True
    assert policy["response_actions"]["max_autonomous_action"] == "BLOCK"
    assert engine.is_usb_threat() is True
    assert engine.is_after_hours_threat() is True


def test_policy_engine_update_and_persist(storage):
    engine = PolicyEngine(storage)

    # Update USB to allowed and auto-containment to False
    updated = engine.update_policy({
        "threat_rules": {"usb_policy": USB_ALLOWED},
        "response_actions": {"auto_containment": False, "max_autonomous_action": "ALERT"},
    })

    assert updated["threat_rules"]["usb_policy"] == USB_ALLOWED
    assert updated["response_actions"]["auto_containment"] is False
    assert updated["response_actions"]["max_autonomous_action"] == "ALERT"

    # Reload from storage to verify durability
    engine2 = PolicyEngine(storage)
    assert engine2.get_policy()["threat_rules"]["usb_policy"] == USB_ALLOWED
    assert engine2.is_usb_threat() is False
    assert engine2.should_emit_directive("BLOCK") is False


def test_usb_policy_rule_filtering(storage):
    engine = PolicyEngine(storage)

    raw_rules = ["after_hours", "removable_device", "write_to_removable", "ml_anomaly"]

    # In default "alert" mode, USB rules are kept
    assert set(engine.filter_fired_rules(raw_rules)) == set(raw_rules)

    # In "allowed" mode, USB rules are filtered out
    engine.update_policy({"threat_rules": {"usb_policy": USB_ALLOWED}})
    filtered = engine.filter_fired_rules(raw_rules)
    assert "removable_device" not in filtered
    assert "write_to_removable" not in filtered
    assert "after_hours" in filtered
    assert "ml_anomaly" in filtered

    # In "disabled" mode, USB rules are also filtered out
    engine.update_policy({"threat_rules": {"usb_policy": USB_DISABLED}})
    filtered_disabled = engine.filter_fired_rules(raw_rules)
    assert "removable_device" not in filtered_disabled
    assert "write_to_removable" not in filtered_disabled


def test_after_hours_rule_filtering(storage):
    engine = PolicyEngine(storage)

    raw_rules = ["after_hours", "large_transfer"]
    assert "after_hours" in engine.filter_fired_rules(raw_rules)

    # Disable after-hours
    engine.update_policy({"threat_rules": {"after_hours_policy": AFTER_HOURS_DISABLED}})
    filtered = engine.filter_fired_rules(raw_rules)
    assert "after_hours" not in filtered
    assert "large_transfer" in filtered


def test_action_enforcement_and_capping(storage):
    engine = PolicyEngine(storage)

    # USB strictly blocked
    engine.update_policy({"threat_rules": {"usb_policy": USB_BLOCKED}})
    assert engine.enforce_action("ALERT", has_usb=True) == "BLOCK"
    assert engine.enforce_action("ALERT", has_usb=False) == "ALERT"

    # Max autonomous action capped to ALERT
    engine.update_policy({
        "threat_rules": {"usb_policy": USB_ALERT},
        "response_actions": {"max_autonomous_action": "ALERT"},
    })
    assert engine.enforce_action("BLOCK") == "ALERT"
    assert engine.enforce_action("DISMISS") == "DISMISS"


def test_agent_policy_sync_payload(storage):
    engine = PolicyEngine(storage)
    agent_dict = engine.agent_policy_dict()
    assert agent_dict["collect_usb"] is True
    assert agent_dict["usb_policy"] == USB_ALERT

    engine.update_policy({"threat_rules": {"usb_policy": USB_DISABLED}})
    agent_dict_disabled = engine.agent_policy_dict()
    assert agent_dict_disabled["collect_usb"] is False
    assert agent_dict_disabled["usb_policy"] == USB_DISABLED


def test_policy_reset(storage):
    engine = PolicyEngine(storage)
    engine.update_policy({"threat_rules": {"usb_policy": USB_ALLOWED}})
    assert engine.get_policy()["threat_rules"]["usb_policy"] == USB_ALLOWED

    reset = engine.reset_policy()
    assert reset["threat_rules"]["usb_policy"] == USB_ALERT
    assert engine.get_policy()["threat_rules"]["usb_policy"] == USB_ALERT


def test_policy_api_endpoints(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from server.main import create_app
    from server.config import ServerConfig
    from server.ml.model import DetectionModel
    from unittest.mock import MagicMock

    root = tmp_path / "api_test"
    root.mkdir()
    cfg = ServerConfig(
        db_path=str(root / "vigil.db"),
        keys_dir=str(root / "keys"),
        model_path=str(root / "model.pkl"),
    )
    from server.keygen import generate
    generate(cfg)

    mock_model = DetectionModel(
        model=MagicMock(),
        feature_cols=["file_count"],
        threshold=0.0,
        meta={},
    )
    monkeypatch.setattr(DetectionModel, "load", lambda path: mock_model)
    app = create_app(cfg)

    with TestClient(app) as client:
        # GET default policy
        res = client.get("/api/policy")
        assert res.status_code == 200
        p = res.json()
        assert p["threat_rules"]["usb_policy"] == USB_ALERT

        # PUT update policy
        put_res = client.put("/api/policy", json={
            "threat_rules": {"usb_policy": USB_ALLOWED},
            "response_actions": {"auto_containment": False},
        })
        assert put_res.status_code == 200
        updated = put_res.json()
        assert updated["threat_rules"]["usb_policy"] == USB_ALLOWED
        assert updated["response_actions"]["auto_containment"] is False

        # Verify GET reflects update
        res2 = client.get("/api/policy")
        assert res2.json()["threat_rules"]["usb_policy"] == USB_ALLOWED

        # POST reset
        reset_res = client.post("/api/policy/reset")
        assert reset_res.status_code == 200
        assert reset_res.json()["threat_rules"]["usb_policy"] == USB_ALERT

