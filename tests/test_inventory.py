"""Tests for socials.inventory."""

import json
import os
import tempfile
from unittest import mock

from socials import inventory


def _make_inventory(machines, tmpdir):
    path = os.path.join(tmpdir, "inventory.json")
    with open(path, "w") as f:
        json.dump(machines, f)
    return path


SAMPLE_MACHINES = [
    {"name": "monitor-01", "ip": "10.0.0.1", "role": "monitor"},
    {"name": "web-prod", "ip": "10.0.0.2", "role": "production"},
    {"name": "db-prod", "ip": "10.0.0.3", "role": "production"},
]


class TestValidation:
    def test_valid_machine_names(self):
        assert inventory.validate_machine_name("web-server")
        assert inventory.validate_machine_name("db.prod.01")
        assert inventory.validate_machine_name("node_exporter")

    def test_invalid_machine_names(self):
        assert not inventory.validate_machine_name("")
        assert not inventory.validate_machine_name("web server")
        assert not inventory.validate_machine_name("rm -rf /")
        assert not inventory.validate_machine_name("$(whoami)")

    def test_valid_ips(self):
        assert inventory.validate_ip("10.0.0.1")
        assert inventory.validate_ip("192.168.1.100")
        assert inventory.validate_ip("255.255.255.255")

    def test_invalid_ips(self):
        assert not inventory.validate_ip("")
        assert not inventory.validate_ip("not-an-ip")
        assert not inventory.validate_ip("10.0.0")
        assert not inventory.validate_ip("10.0.0.1.2")


class TestLoadSave:
    def test_load_missing_file(self):
        with mock.patch.object(inventory, "inventory_path", return_value="/nonexistent/inv.json"):
            assert inventory.load() == []

    def test_load_existing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _make_inventory(SAMPLE_MACHINES, tmpdir)
            with mock.patch.object(inventory, "inventory_path", return_value=path):
                machines = inventory.load()
                assert len(machines) == 3
                assert machines[0]["name"] == "monitor-01"

    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "inventory.json")
            with mock.patch.object(inventory, "inventory_path", return_value=path):
                inventory.save(SAMPLE_MACHINES)
                loaded = inventory.load()
                assert len(loaded) == 3
                assert loaded[1]["ip"] == "10.0.0.2"

    def test_save_atomic_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "inventory.json")
            assert not os.path.exists(path)
            with mock.patch.object(inventory, "inventory_path", return_value=path):
                inventory.save([{"name": "test", "ip": "1.2.3.4"}])
                assert os.path.exists(path)
                with open(path) as f:
                    data = json.load(f)
                assert data[0]["name"] == "test"


class TestQuery:
    def test_find_existing(self):
        result = inventory.find("web-prod", SAMPLE_MACHINES)
        assert result is not None
        assert result["ip"] == "10.0.0.2"

    def test_find_missing(self):
        assert inventory.find("nonexistent", SAMPLE_MACHINES) is None

    def test_monitor(self):
        mon = inventory.monitor(SAMPLE_MACHINES)
        assert mon is not None
        assert mon["name"] == "monitor-01"
        assert mon["role"] == "monitor"

    def test_monitor_missing(self):
        no_monitor = [m for m in SAMPLE_MACHINES if m["role"] != "monitor"]
        assert inventory.monitor(no_monitor) is None

    def test_production_machines(self):
        prod = inventory.production_machines(SAMPLE_MACHINES)
        assert len(prod) == 2
        assert all(m["role"] == "production" for m in prod)


class TestUpdate:
    def test_update_in_place(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _make_inventory(SAMPLE_MACHINES, tmpdir)
            with mock.patch.object(inventory, "inventory_path", return_value=path):
                def add_tag(machines):
                    for m in machines:
                        m["tagged"] = True

                inventory.update(add_tag)
                loaded = inventory.load()
                assert all(m.get("tagged") for m in loaded)

    def test_update_with_return(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _make_inventory(SAMPLE_MACHINES, tmpdir)
            with mock.patch.object(inventory, "inventory_path", return_value=path):
                def keep_prod(machines):
                    return [m for m in machines if m["role"] == "production"]

                inventory.update(keep_prod)
                loaded = inventory.load()
                assert len(loaded) == 2


class TestLock:
    def test_lock_reentrant(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "inventory.json")
            lock_path = path + ".lock"
            with mock.patch.object(inventory, "inventory_path", return_value=path):
                with inventory.lock():
                    assert inventory._lock_depth == 1
                    with inventory.lock():
                        assert inventory._lock_depth == 2
                    assert inventory._lock_depth == 1
                assert inventory._lock_depth == 0
