"""Tests for validate-feed-state.py and feed-state-schema.json.

The validator is hand-written and does not read the schema file, so the two
can drift apart. These tests hold them to the same list of feeds and check the
Exodus tracker-list entry that /update-rules writes.
"""
import copy
import importlib.util
import json
import pathlib

import jsonschema
import pytest

THIS_DIR = pathlib.Path(__file__).parent


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


v = _load(THIS_DIR / "validate-feed-state.py", "validate_feed_state")
SCHEMA = json.loads((THIS_DIR / "feed-state-schema.json").read_text(encoding="utf-8"))
LIVE = json.loads((THIS_DIR.parent / "feed-state.json").read_text(encoding="utf-8"))


def _state():
    return copy.deepcopy(LIVE)


def test_live_feed_state_passes_both_checks():
    assert v.validate(LIVE) == []
    jsonschema.validate(LIVE, SCHEMA)
    assert "exodus_trackers" in LIVE["feeds"]


def test_schema_and_validator_list_the_same_feeds():
    feeds = SCHEMA["properties"]["feeds"]
    assert set(feeds["properties"]) == set(v.FEED_SPEC)
    assert set(feeds["required"]) == set(v.FEED_SPEC) - v.OPTIONAL_FEEDS


def test_exodus_entry_is_required():
    state = _state()
    del state["feeds"]["exodus_trackers"]
    assert "feeds.exodus_trackers: missing" in v.validate(state)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(state, SCHEMA)


def test_exodus_entry_needs_only_the_check_time():
    state = _state()
    state["feeds"]["exodus_trackers"] = {"last_seen_timestamp": "2026-11-10T09:00:00Z"}
    assert v.validate(state) == []
    jsonschema.validate(state, SCHEMA)


def test_unknown_feed_is_rejected_by_both():
    state = _state()
    state["feeds"]["exodus"] = {"last_seen_timestamp": "2026-11-10T00:00:00Z"}
    assert any("feeds.exodus: unknown feed" in e for e in v.validate(state))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(state, SCHEMA)


def test_exodus_entry_rejects_extra_keys():
    state = _state()
    state["feeds"]["exodus_trackers"]["tracker_count"] = 428
    assert "feeds.exodus_trackers: unexpected key 'tracker_count'" in v.validate(state)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(state, SCHEMA)


@pytest.mark.parametrize("key", ["last_seen_timestamp", "ioc_data_last_write"])
def test_exodus_entry_rejects_a_bad_timestamp(key):
    state = _state()
    state["feeds"]["exodus_trackers"][key] = "yesterday"
    assert any(e.startswith(f"feeds.exodus_trackers.{key}:") for e in v.validate(state))
