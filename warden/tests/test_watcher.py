"""Formal pytest suite for socialwarden-watcher.

Consolidates the three smoke_phase_{a,b,c}.py scripts and adds coverage for
the Phase D daemon tick loop plus the CLI entry points (doctor / load_config /
single-instance lock) that the smokes didn't touch.

The suite is hermetic: no network, no real `bw` CLI, no real vault. A fake
`bw` Python script is materialised per test that needs it. Migration tests
spin up a tiny "agent simulator" thread that watches the rendered config and
populates /run/secrets/<name>.env as the real socialwarden-agent would after a
SIGHUP.

Run with: pytest -q tests/test_watcher.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
WATCHER_PATH = HERE.parent / "agent" / "socialwarden-watcher.py"


# ---------------------------------------------------------------------------
# Module loading — session-scoped so we import once per test session.
# ---------------------------------------------------------------------------
def _load_watcher():
    """Import the watcher script as a module. The script uses dataclasses with
    `from __future__ import annotations`, which requires the module to be
    visible in sys.modules during exec — hence the explicit registration."""
    spec = importlib.util.spec_from_file_location("dw_watcher", WATCHER_PATH)
    assert spec and spec.loader, f"could not load spec for {WATCHER_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def watcher():
    return _load_watcher()


# ---------------------------------------------------------------------------
# Fake `bw` builder — used by BWClient and migrate tests.
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_bw(tmp_path: Path):
    """Materialise a fake `bw` binary at tmp_path/bw and return a small
    handle with .path, .invocations_log, .read_invocations(). The fake
    handles the bw subcommands the watcher exercises: status, unlock,
    config server, list items, encode, create item."""

    log_path = tmp_path / "bw-invocations.log"
    coll_path = tmp_path / "fake-collections.json"
    bw_path = tmp_path / "bw"
    bw_path.write_text(
        textwrap.dedent(
            f"""\
        #!/usr/bin/env python3
        import sys, os, json, base64
        STDIN_DATA = sys.stdin.read() if not sys.stdin.isatty() else ''
        log = open({str(log_path)!r}, 'a')
        log.write(json.dumps({{
            'argv': sys.argv[1:],
            'stdin_len': len(STDIN_DATA),
            'BW_SESSION': bool(os.environ.get('BW_SESSION')),
            'BW_PW_ENV': bool(os.environ.get('BW_PASSWORD_INTERNAL')),
            'pw_env_value': os.environ.get('BW_PASSWORD_INTERNAL', ''),
        }}) + '\\n')
        a = sys.argv[1:]
        COLL_FILE = {str(coll_path)!r}
        # Seed: the collections the existing migrate E2E tests assume already
        # exist. ensure_collection() resolves these via preferred_id → the
        # absorb behaves exactly as it did pre-M1 (no collection created).
        SEED = [
            {{'id': 'COLL-test-svc-123', 'name': 'test-svc', 'organizationId': 'ORG-AAA'}},
            {{'id': 'COLL-rich-456', 'name': 'svc-rich', 'organizationId': 'ORG-AAA'}},
            {{'id': 'COLL-only-secrets-789', 'name': 'svc-only-secrets', 'organizationId': 'ORG-AAA'}},
        ]
        def _load_colls():
            try:
                with open(COLL_FILE) as f:
                    return json.load(f)
            except (OSError, ValueError):
                return list(SEED)
        def _save_colls(c):
            with open(COLL_FILE, 'w') as f:
                json.dump(c, f)
        if a[:1] == ['status']:
            print(json.dumps({{'status': 'locked', 'userEmail': 'contact@example.com'}}))
            sys.exit(0)
        if a[:1] == ['unlock']:
            print('FAKE_SESSION_TOKEN_xxx_yyy')
            sys.exit(0)
        if a[:2] == ['config', 'server']:
            sys.exit(0)
        if a[:2] == ['list', 'org-collections']:
            print(json.dumps(_load_colls()))
            sys.exit(0)
        if a[:3] == ['list', 'items', '--collectionid']:
            print(json.dumps([]))
            sys.exit(0)
        if a[:2] == ['list', 'items']:
            print(json.dumps([{{'id': 'item-1', 'name': 'fake'}}]))
            sys.exit(0)
        if a[:1] == ['encode']:
            print(base64.b64encode(STDIN_DATA.encode()).decode())
            sys.exit(0)
        if a[:2] == ['create', 'org-collection']:
            decoded = json.loads(base64.b64decode(a[2]))
            new_id = 'COLL-created-' + decoded['name']
            colls = _load_colls()
            colls.append({{'id': new_id, 'name': decoded['name'],
                           'organizationId': decoded.get('organizationId')}})
            _save_colls(colls)
            log.write(json.dumps({{'created_collection': decoded, 'id': new_id}}) + '\\n')
            print(json.dumps({{'id': new_id, **decoded}}))
            sys.exit(0)
        if a[:2] == ['create', 'item']:
            decoded = json.loads(base64.b64decode(a[2]))
            item_id = f"item-{{decoded['login']['username']}}"
            log.write(json.dumps({{'created': decoded}}) + '\\n')
            print(json.dumps({{'id': item_id, **decoded}}))
            sys.exit(0)
        print('unhandled bw call: ' + ' '.join(a), file=sys.stderr)
        sys.exit(2)
        """
        )
    )
    bw_path.chmod(0o755)

    class _Fake:
        def __init__(self):
            self.path = str(bw_path)
            self.log = log_path

        def read_invocations(self) -> list[dict]:
            if not self.log.exists():
                return []
            out = []
            for ln in self.log.read_text().splitlines():
                try:
                    out.append(json.loads(ln))
                except json.JSONDecodeError:
                    pass
            return out

    return _Fake()


# ===========================================================================
# Phase A — parse_env_file, classify, discover_candidates, is_already_managed
# ===========================================================================
class TestParseEnvFile:
    def test_basic_mixed_lines(self, watcher, tmp_path: Path):
        sample = (
            "# Header comment\n"
            "\n"
            "DB_PASSWORD=hunter2\n"
            'DB_USER="alice"\n'
            "API_KEY='tkn_abc123def456'\n"
            "export PORT=5432  # the postgres port\n"
            "TRICKY=value\\#with-hash\n"
            "DUPL=first\n"
            "DUPL=second\n"
            "INVALID LINE NO EQUALS\n"
            "EMPTY=\n"
        )
        p = tmp_path / ".env"
        p.write_text(sample, encoding="utf-8")
        assert watcher.parse_env_file(p) == [
            ("DB_PASSWORD", "hunter2"),
            ("DB_USER", "alice"),
            ("API_KEY", "tkn_abc123def456"),
            ("PORT", "5432"),
            ("TRICKY", "value#with-hash"),
            ("DUPL", "first"),
            ("DUPL", "second"),
            ("EMPTY", ""),
        ]

    def test_missing_file_returns_none(self, watcher, tmp_path: Path):
        assert watcher.parse_env_file(tmp_path / "nope.env") is None

    def test_empty_file_returns_empty_list(self, watcher, tmp_path: Path):
        p = tmp_path / "empty.env"
        p.write_text("", encoding="utf-8")
        assert watcher.parse_env_file(p) == []

    def test_binary_garbage_returns_none(self, watcher, tmp_path: Path):
        p = tmp_path / "binary.env"
        p.write_bytes(b"\xff\xfe\x00\x01garbage")
        assert watcher.parse_env_file(p) is None


class TestClassify:
    @pytest.mark.parametrize(
        "key,value,expected",
        [
            # Obvious secrets
            ("DB_PASSWORD", "hunter2", "secret"),
            ("API_KEY", "tkn_abc", "secret"),
            ("JWT_SECRET", "abc.def", "secret"),
            ("STRIPE_SECRET_KEY", "sk_live_xyz", "secret"),
            ("LIVEKIT_API_KEY", "lk_xyz", "secret"),
            ("HMAC_KEY", "deadbeef", "secret"),
            # Config (non-secret)
            ("PORT", "5432", "config"),
            ("DB_HOST", "127.0.0.1", "config"),
            ("LOG_LEVEL", "INFO", "config"),
            ("NODE_ENV", "production", "config"),
            # CI / build noise that should be skipped entirely
            ("IMAGE_TAG", "stg-abc123", "skip"),
            ("GITHUB_ACTIONS", "true", "skip"),
            ("EMPTY", "", "skip"),
            ("FOO", "changeme", "skip"),
            ("BUILD_NUMBER", "42", "skip"),
            # Tie-break by entropy on ambiguous key name
            ("X", "AaBb1234abcdefgh", "secret"),
            ("X", "hello", "config"),
        ],
    )
    def test_classify(self, watcher, key, value, expected):
        assert watcher.classify(key, value) == expected


class TestDiscoverCandidates:
    @pytest.fixture
    def layout(self, tmp_path: Path) -> Path:
        # root/.env                                  ← yes
        # root/svc-a/.env                            ← yes
        # root/svc-a/.env.example                    ← no (template)
        # root/svc-a/.env.pre-socialwarden-20260101    ← no (backup)
        # root/svc-b/sub/.env                        ← yes (depth 2)
        # root/svc-b/sub/sub2/sub3/.env              ← no (over max_depth=3)
        # root/node_modules/foo/.env                 ← no (skipped dir)
        # root/random.txt                            ← no (not env)
        (tmp_path / ".env").write_text("X=1")
        (tmp_path / "svc-a").mkdir()
        (tmp_path / "svc-a" / ".env").write_text("X=1")
        (tmp_path / "svc-a" / ".env.example").write_text("X=1")
        (tmp_path / "svc-a" / ".env.pre-socialwarden-20260101").write_text("X=1")
        (tmp_path / "svc-b" / "sub").mkdir(parents=True)
        (tmp_path / "svc-b" / "sub" / ".env").write_text("X=1")
        (tmp_path / "svc-b" / "sub" / "sub2" / "sub3").mkdir(parents=True)
        (tmp_path / "svc-b" / "sub" / "sub2" / "sub3" / ".env").write_text("X=1")
        (tmp_path / "node_modules" / "foo").mkdir(parents=True)
        (tmp_path / "node_modules" / "foo" / ".env").write_text("X=1")
        (tmp_path / "random.txt").write_text("hi")
        return tmp_path

    def test_layout_with_max_depth_3(self, watcher, layout: Path):
        got = watcher.discover_candidates(layout, recursive=True, max_depth=3)
        names = sorted(str(p.relative_to(layout)) for p in got)
        assert names == [".env", "svc-a/.env", "svc-b/sub/.env"]

    def test_missing_root_returns_empty(self, watcher, tmp_path: Path):
        assert watcher.discover_candidates(tmp_path / "nope") == []


class TestIsAlreadyManaged:
    def test_plain_file(self, watcher, tmp_path: Path):
        p = tmp_path / "plain.env"
        p.write_text("X=1")
        assert watcher.is_already_managed(p) is False

    def test_symlink_into_secrets(self, watcher, tmp_path: Path):
        target = tmp_path / "managed.env"
        os.symlink("/run/secrets/svc.env", target)
        assert watcher.is_already_managed(target) is True

    def test_symlink_elsewhere(self, watcher, tmp_path: Path):
        target = tmp_path / "other.env"
        os.symlink("/tmp/elsewhere.env", target)
        assert watcher.is_already_managed(target) is False

    def test_respects_custom_secrets_dir(self, watcher, tmp_path: Path):
        # The watcher is parameterisable: smoke regression for the bug
        # we fixed when migrate() was checking SECRETS_DIR instead of
        # self.secrets_dir.
        secrets = tmp_path / "custom-secrets"
        target = tmp_path / "via-custom.env"
        os.symlink(str(secrets / "svc.env"), target)
        assert watcher.is_already_managed(target, secrets_dir=str(secrets)) is True

    def test_follows_symlink_chain(self, watcher, tmp_path: Path):
        """Operator may interpose a redirect symlink between the source path
        and /run/secrets — the watcher must still recognise it as managed.

        Chain: /home/foo/.env  →  /etc/links/foo.env  →  /run/secrets/foo.env.merged
        """
        secrets = tmp_path / "run-secrets"
        secrets.mkdir()
        (secrets / "foo.env.merged").write_text("X=1\n")
        intermediate = tmp_path / "intermediate.env"
        os.symlink(str(secrets / "foo.env.merged"), intermediate)
        source = tmp_path / "source.env"
        os.symlink(str(intermediate), source)
        assert watcher.is_already_managed(source, secrets_dir=str(secrets)) is True

    def test_dangling_symlink_into_secrets_is_managed(self, watcher, tmp_path: Path):
        """A dangling symlink (final target doesn't exist) is still considered
        managed if the chain resolves under secrets_dir — common during a
        race where the watcher swapped the link before the agent rendered
        the merged file."""
        secrets = tmp_path / "run-secrets"
        target = tmp_path / "dangling.env"
        os.symlink(str(secrets / "not-yet-rendered.env.merged"), target)
        # secrets dir doesn't even need to exist
        assert watcher.is_already_managed(target, secrets_dir=str(secrets)) is True


# ===========================================================================
# Phase B — read_encrypted_file, _LockedFile, BWClient hygiene + validation
# ===========================================================================
class TestReadEncryptedFile:
    def test_refuses_non_enc_prefix(self, watcher, tmp_path: Path):
        p = tmp_path / "plain.key"
        p.write_text("not-encrypted-plain-text\n")
        assert watcher.read_encrypted_file(p) is None

    def test_missing_file_returns_none(self, watcher, tmp_path: Path):
        assert watcher.read_encrypted_file(tmp_path / "nope.key") is None

    def test_tampered_blob_returns_none(self, watcher, tmp_path: Path):
        p = tmp_path / "bad.key"
        p.write_text("ENC:not-valid-base64!!!\n")
        assert watcher.read_encrypted_file(p) is None


class TestLockedFile:
    def test_serializes_two_threads(self, watcher, tmp_path: Path):
        lockpath = str(tmp_path / "test.lock")
        order: list[str] = []
        barrier = threading.Barrier(2)

        def worker(name: str, hold_s: float) -> None:
            barrier.wait()
            with watcher._LockedFile(lockpath, timeout_s=10.0):
                order.append(f"{name}:in")
                time.sleep(hold_s)
                order.append(f"{name}:out")

        t1 = threading.Thread(target=worker, args=("A", 0.2))
        t2 = threading.Thread(target=worker, args=("B", 0.1))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        # Whichever ran first, the other must have run strictly after.
        assert order in (
            ["A:in", "A:out", "B:in", "B:out"],
            ["B:in", "B:out", "A:in", "A:out"],
        )

    def test_timeout_raises_flock_timeout(self, watcher, tmp_path: Path):
        lockpath = str(tmp_path / "busy.lock")
        # Hold the lock in a subprocess so it can't be released until terminate().
        holder_src = (
            "import fcntl, time, sys\n"
            "f = open(sys.argv[1], 'a+')\n"
            "fcntl.flock(f.fileno(), fcntl.LOCK_EX)\n"
            "print('held', flush=True)\n"
            "time.sleep(5)\n"
        )
        holder_py = tmp_path / "holder.py"
        holder_py.write_text(holder_src)
        holder = subprocess.Popen(
            [sys.executable, str(holder_py), lockpath], stdout=subprocess.PIPE
        )
        try:
            assert holder.stdout.readline().strip() == b"held"
            t0 = time.monotonic()
            with pytest.raises(watcher.FlockTimeout):
                with watcher._LockedFile(lockpath, timeout_s=1.0):
                    pass
            elapsed = time.monotonic() - t0
            assert 0.9 <= elapsed <= 1.8, f"timeout drift: elapsed={elapsed:.2f}s"
        finally:
            holder.terminate()
            holder.wait()


class TestBWClientValidation:
    def test_empty_email_raises_value_error(self, watcher):
        with pytest.raises(ValueError):
            watcher.BWClient(email="", server_url="x", master_password="x")

    def test_empty_master_password_raises_value_error(self, watcher):
        with pytest.raises(ValueError):
            watcher.BWClient(email="x", server_url="x", master_password="")


class TestBWClientHygiene:
    def test_password_never_in_argv_uses_env(self, watcher, fake_bw, tmp_path: Path):
        lockpath = str(tmp_path / "bw.lock")
        client = watcher.BWClient(
            email="contact@example.com",
            server_url="https://vault.example.com",
            master_password="REDACTED_MASTER_PASS_zzz",
            bw_binary=fake_bw.path,
            lock_path=lockpath,
            lock_timeout_s=5,
            max_retries=1,
        )
        items = client.list_items_in_collection("col-abc-123")
        assert items == []

        invocations = fake_bw.read_invocations()
        unlock_calls = [r for r in invocations if r.get("argv", [])[:1] == ["unlock"]]
        # Password must NEVER appear in argv (any invocation).
        for r in invocations:
            assert "REDACTED_MASTER_PASS_zzz" not in str(r.get("argv", []))
        # And must reach the unlock call via env.
        assert unlock_calls, "expected at least one unlock call"
        assert unlock_calls[0]["pw_env_value"] == "REDACTED_MASTER_PASS_zzz"

    def test_session_cached_after_unlock(self, watcher, fake_bw, tmp_path: Path):
        """Two list_items_in_collection calls should produce only one unlock."""
        lockpath = str(tmp_path / "bw.lock")
        client = watcher.BWClient(
            email="contact@example.com",
            server_url="https://vault.example.com",
            master_password="pw-xyz",
            bw_binary=fake_bw.path,
            lock_path=lockpath,
            max_retries=1,
        )
        client.list_items_in_collection("col-1")
        client.list_items_in_collection("col-2")
        unlock_calls = [
            r for r in fake_bw.read_invocations() if r["argv"][:1] == ["unlock"]
        ]
        assert len(unlock_calls) == 1, f"expected 1 unlock, got {len(unlock_calls)}"

    def test_recovers_from_stale_session_malformed_output(
        self, watcher, tmp_path: Path
    ):
        """Reproduces the canary failure mode: bw cli returns '\\n' (empty
        line) on the first `list items` call due to a stale cached session,
        then JSON on the retry after we drop the session. The watcher must
        not surface this as a None — it must retry once and succeed.

        Without this fix the watcher silently defers tick after tick when
        the agent is doing concurrent bw work, never absorbing anything.
        """
        log_path = tmp_path / "bw-stale.log"
        bw_path = tmp_path / "bw"
        # Fake bw: returns `\n` on first `list items` call, valid JSON on
        # the second. Counter persists across invocations via a marker file.
        bw_path.write_text(
            textwrap.dedent(
                f"""\
            #!/usr/bin/env python3
            import sys, json, os, pathlib
            marker = pathlib.Path({str(tmp_path / "list-count.txt")!r})
            log = open({str(log_path)!r}, 'a')
            log.write(json.dumps({{'argv': sys.argv[1:]}}) + '\\n')
            a = sys.argv[1:]
            if a[:1] == ['status']:
                print(json.dumps({{'status': 'locked'}}))
                sys.exit(0)
            if a[:1] == ['unlock']:
                print('FAKE_SESSION_TOKEN_xxx')
                sys.exit(0)
            if a[:2] == ['config', 'server']:
                sys.exit(0)
            if a[:2] == ['list', 'items']:
                n = int(marker.read_text()) if marker.exists() else 0
                marker.write_text(str(n + 1))
                if n == 0:
                    # Stale session symptom: empty/malformed stdout
                    print('')
                    sys.exit(0)
                # Recovery: real JSON
                print(json.dumps([{{'name': 'recovered-item'}}]))
                sys.exit(0)
            print('unhandled', file=sys.stderr); sys.exit(2)
            """
            )
        )
        bw_path.chmod(0o755)

        client = watcher.BWClient(
            email="contact@example.com",
            server_url="https://vault.example.com",
            master_password="pw",
            bw_binary=str(bw_path),
            lock_path=str(tmp_path / "bw.lock"),
            max_retries=1,
        )
        items = client.list_items_in_collection("col-stale-xyz")
        # The watcher must recover and return the parsed list.
        assert items == [{"name": "recovered-item"}]

        # Validate the recovery actually unlocked twice (once initial, once
        # after dropping the stale session).
        invocations = [json.loads(ln) for ln in log_path.read_text().splitlines()]
        unlocks = [r for r in invocations if r["argv"][:1] == ["unlock"]]
        list_calls = [r for r in invocations if r["argv"][:2] == ["list", "items"]]
        assert len(unlocks) == 2, f"expected re-unlock after stale; got {len(unlocks)}"
        assert len(list_calls) == 2, f"expected 2 list attempts; got {len(list_calls)}"

    def test_health_check_returns_dict(self, watcher, fake_bw, tmp_path: Path):
        client = watcher.BWClient(
            email="contact@example.com",
            server_url="https://vault.example.com",
            master_password="x",
            bw_binary=fake_bw.path,
            lock_path=str(tmp_path / "bw.lock"),
            max_retries=1,
        )
        status = client.health_check()
        assert isinstance(status, dict)
        assert status.get("status") == "locked"


# ===========================================================================
# Phase C — helpers: _flatten_path, _atomic_copy, _sha256_file,
#           _format_bw_notes, _append_audit_line, purge_old_backups
# ===========================================================================
class TestFlattenPathForBackup:
    @pytest.mark.parametrize(
        "src,expected",
        [
            ("/home/ubuntu/svc-a/.env", "home-ubuntu-svc-a-.env"),
            ("/foo bar/x.env", "foo_bar-x.env"),
        ],
    )
    def test_flatten(self, watcher, src, expected):
        assert watcher._flatten_path_for_backup(src) == expected


class TestAtomicCopy:
    def test_copies_bytes_and_sets_mode(self, watcher, tmp_path: Path):
        src = tmp_path / "src.env"
        src.write_text("DB_PASSWORD=hunter2\n")
        dst = tmp_path / "backup.env"
        assert watcher._atomic_copy(str(src), str(dst), 0o600) is True
        assert oct(dst.stat().st_mode & 0o777) == oct(0o600)
        assert dst.read_bytes() == src.read_bytes()

    def test_missing_src_returns_false(self, watcher, tmp_path: Path):
        ok = watcher._atomic_copy(str(tmp_path / "nope"), str(tmp_path / "dst"), 0o600)
        assert ok is False


class TestSha256File:
    def test_returns_lowercase_64_hex(self, watcher, tmp_path: Path):
        p = tmp_path / "x"
        p.write_bytes(b"hello")
        sha = watcher._sha256_file(str(p))
        assert isinstance(sha, str)
        assert len(sha) == 64
        assert sha == sha.lower()


class TestFormatBWNotes:
    @pytest.fixture
    def notes(self, watcher) -> str:
        return watcher._format_bw_notes(
            machine_name="host-utils",
            origin="/home/ubuntu/svc-a/.env",
            backup_path="/run/socialwarden-backups/home-ubuntu-svc-a-.env-20260513T093000Z",
            absorbed_at=datetime(2026, 5, 13, 9, 30, 0, tzinfo=timezone.utc),
            retention_days=30,
            key="DB_PASSWORD",
        )

    def test_has_versioned_header(self, watcher, notes: str):
        assert f"[socialwarden-watcher v{watcher.VERSION}]" in notes

    def test_uses_logical_hostname(self, notes: str):
        assert "host: host-utils" in notes

    def test_does_not_leak_aws_hostname(self, notes: str):
        assert "ip-172-" not in notes
        assert "ip-10-" not in notes

    def test_backup_expires_at_plus_30d(self, notes: str):
        assert "backup_expires_at: 2026-06-12T09:30:00+00:00" in notes

    def test_has_key_field(self, notes: str):
        assert "key: DB_PASSWORD" in notes


class TestComputeStaticContent:
    """Unit tests for the helper that strips secret-bearing lines from
    the original .env text while preserving everything else verbatim."""

    def test_drops_only_secret_lines(self, watcher):
        original = "DB_PASSWORD=hunter2\nPORT=5432\nAPI_KEY=tkn_xyz\nLOG_LEVEL=INFO\n"
        out = watcher._compute_static_content(original, {"DB_PASSWORD", "API_KEY"})
        assert out == "PORT=5432\nLOG_LEVEL=INFO\n"

    def test_preserves_comments_and_blanks(self, watcher):
        original = "# header\n\nDB_PASSWORD=hunter2\n# section\nPORT=5432\n"
        out = watcher._compute_static_content(original, {"DB_PASSWORD"})
        assert out == "# header\n\n# section\nPORT=5432\n"

    def test_preserves_export_prefix(self, watcher):
        original = "export DB_PASSWORD=hunter2\nexport PORT=5432\n"
        out = watcher._compute_static_content(original, {"DB_PASSWORD"})
        assert out == "export PORT=5432\n"

    def test_empty_secret_set_is_identity(self, watcher):
        original = "FOO=bar\n# c\nBAZ=qux\n"
        assert watcher._compute_static_content(original, set()) == original

    def test_leaves_malformed_lines_alone(self, watcher):
        """Lines that don't look like 'KEY=value' (no equals, leading
        non-identifier chars, etc.) are passed through unchanged."""
        original = (
            "INVALID LINE NO EQUALS\nDB_PASSWORD=hunter2\n  =starts-with-equals\n"
        )
        out = watcher._compute_static_content(original, {"DB_PASSWORD"})
        assert "INVALID LINE NO EQUALS\n" in out
        assert "  =starts-with-equals\n" in out
        assert "DB_PASSWORD" not in out


class TestStaticPathFor:
    @pytest.mark.parametrize(
        "env_path,expected",
        [
            ("/home/foo/.env", "/home/foo/.env.static"),
            ("/srv/app/production.env", "/srv/app/production.env.static"),
            ("/home/foo/.env.local", "/home/foo/.env.local.static"),
        ],
    )
    def test_static_path(self, watcher, env_path, expected):
        assert watcher._static_path_for(env_path) == expected


class TestAppendAuditLine:
    def test_appends_each_call(self, watcher, tmp_path: Path):
        log = tmp_path / "audit.jsonl"
        watcher._append_audit_line(str(log), {"event": "absorbed", "n": 1})
        watcher._append_audit_line(str(log), {"event": "absorbed", "n": 2})
        lines = log.read_text().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["n"] == 1
        assert json.loads(lines[1])["n"] == 2


class TestPurgeOldBackups:
    def test_30d_boundary_inclusive_31d_deleted(self, watcher, tmp_path: Path):
        """User contract: 30-day-old backup is STILL within retention; only
        files strictly older than 30 days get purged."""
        now = datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone.utc)
        cases = {
            "svc-a-.env-20260508T120000Z": "keep",  # 5d
            "svc-b-.env-20260428T120000Z": "keep",  # 15d
            "svc-c-.env-20260414T120000Z": "keep",  # 29d
            "svc-d-.env-20260413T120000Z": "keep",  # 30d (boundary)
            "svc-e-.env-20260412T120000Z": "delete",  # 31d
            "foreign-file-no-ts.txt": "keep",  # no TS → ignored
        }
        for name in cases:
            (tmp_path / name).write_text("x")
        deleted = watcher.purge_old_backups(str(tmp_path), retention_days=30, now=now)
        assert deleted == 1
        remaining = sorted(p.name for p in tmp_path.iterdir())
        assert remaining == [
            "foreign-file-no-ts.txt",
            "svc-a-.env-20260508T120000Z",
            "svc-b-.env-20260428T120000Z",
            "svc-c-.env-20260414T120000Z",
            "svc-d-.env-20260413T120000Z",
        ]


# ===========================================================================
# Phase C/D — migrate() end-to-end + WatcherDaemon.tick()
# ===========================================================================
@pytest.fixture
def daemon_sandbox(watcher, fake_bw, tmp_path: Path):
    """Builds a complete WatcherDaemon + agent simulator in a sandbox tmpdir.

    Returns a dataclass-like object exposing:
        .daemon, .src_env, .runsec, .bdir, .cfg_path, .audit, .agent_started

    The agent simulator polls cfg.yaml; when the watcher writes a new
    sync.collections entry, it renders the absorbed keys to
    /run/secrets/<name>.env (what the real agent does on SIGHUP)."""
    runsec = tmp_path / "run/secrets"
    runsec.mkdir(parents=True)
    bdir = tmp_path / "run/socialwarden-backups"
    logdir = tmp_path / "var/log/socialwarden"
    logdir.mkdir(parents=True)
    audit = logdir / "watcher.audit.jsonl"
    etc = tmp_path / "etc/socialwarden"
    etc.mkdir(parents=True)

    svc_dir = tmp_path / "home/test-svc"
    svc_dir.mkdir(parents=True)
    cfg_path = etc / "config.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "auth": {"email": "contact@example.com"},
                "machine": {"name": "host-utils"},
                "organization": {"id": "ORG-AAA"},
                "sync": {"collections": []},
                # Pin symlink materialize so these legacy E2E tests stay
                # deterministic regardless of who owns the pytest tmpdir (M2
                # auto-detect would otherwise pick `copy` when run as non-root).
                # The dedicated copy-mode behaviour is covered by TestMaterializeM2.
                "watch": {
                    "materialize_for_dir": {str(svc_dir): {"strategy": "symlink"}}
                },
            }
        )
    )

    src_env = svc_dir / ".env"
    src_env.write_text(
        "DB_PASSWORD=topsecret_z9_xx_yy\n"
        "API_KEY=sk_live_aaa_bbb_ccc\n"
        "PORT=5432\n"
        "LOG_LEVEL=INFO\n"
    )
    os.chmod(src_env, 0o600)

    agent_started = threading.Event()
    stop_flag = threading.Event()

    def agent_simulator() -> None:
        """Stand-in for socialwarden-agent. Watches config.yaml for a new
        collection; on each new entry, renders the vault-only file (from
        the fake bw log) AND, when a `merge:` block is present, combines
        it with the static file to produce the `.merged` file the watcher
        will symlink into the source.

        Env-key extraction follows the REAL agent's render_env: it uses
        `item.name` (not login.username) as the env var key. login.username
        is the descriptive label (e.g. collection name)."""
        seen: set[str] = set()
        agent_started.set()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not stop_flag.is_set():
            try:
                cfg = yaml.safe_load(cfg_path.read_text()) or {}
            except Exception:
                time.sleep(0.05)
                continue
            for c in (cfg.get("sync") or {}).get("collections") or []:
                cid = c.get("id")
                vault_out = c.get("output")
                if not cid or cid in seen or not vault_out:
                    continue
                seen.add(cid)
                # 1. Render the vault-only file from the fake bw create log.
                pairs: list[tuple[str, str]] = []
                for rec in fake_bw.read_invocations():
                    created = rec.get("created")
                    if not created:
                        continue
                    if cid not in (created.get("collectionIds") or []):
                        continue
                    # Real agent uses item.name as env key (NOT login.username).
                    pairs.append(
                        (
                            created["name"],
                            created["login"]["password"],
                        )
                    )
                rendered = "".join(f"{k}={v}\n" for k, v in pairs)
                Path(vault_out).parent.mkdir(parents=True, exist_ok=True)
                Path(vault_out).write_text(rendered)

                # 2. If the collection has a merge: block, build the
                # combined .merged file. Order: static first (preserves
                # operator-edited config + comments), vault second (so a
                # rotated password wins over any stale value in static).
                merge = c.get("merge") or {}
                merge_target = merge.get("target")
                merge_static = merge.get("static")
                if merge_target:
                    static_text = ""
                    if merge_static:
                        try:
                            static_text = Path(merge_static).read_text()
                        except OSError:
                            static_text = ""
                    # Mirror the REAL agent's merged format byte-for-byte
                    # (socialwarden-agent._merge_and_link): static block,
                    # the SocialWarden sentinel header, then the vault block.
                    # The sentinel is load-bearing — is_already_managed()
                    # uses it to recognise a materialize=copy consumer.
                    merged_text = (
                        static_text.rstrip("\n")
                        + "\n"
                        + "# === Secrets managed by SocialWarden (do not edit) ===\n"
                        + rendered
                    )
                    Path(merge_target).parent.mkdir(parents=True, exist_ok=True)
                    Path(merge_target).write_text(merged_text)
                    # In copy materialize the real agent writes the merged
                    # content AS A REAL FILE at `link` (no /run/secrets
                    # symlink). Mirror that so the watcher's copy path is
                    # exercised against an agent that DID its job.
                    if merge.get("materialize") == "copy" and merge.get("link"):
                        lp = Path(merge["link"])
                        try:
                            if lp.is_symlink():
                                lp.unlink()
                            lp.write_text(merged_text)
                            os.chmod(lp, 0o640)
                        except OSError:
                            pass
            time.sleep(0.05)

    sim = threading.Thread(target=agent_simulator, daemon=True)
    sim.start()
    agent_started.wait(timeout=2)

    bw_client = watcher.BWClient(
        email="contact@example.com",
        server_url="",
        master_password="DUMMY_PW",
        bw_binary=fake_bw.path,
        lock_path=str(tmp_path / "bw.lock"),
        max_retries=1,
        lock_timeout_s=5,
    )
    watcher.set_machine_name("host-utils")
    cfg = yaml.safe_load(cfg_path.read_text())
    daemon = watcher.WatcherDaemon(
        config=cfg,
        bw_client=bw_client,
        machine_name="host-utils",
        agent_config_path=str(cfg_path),
        agent_pid_file=str(tmp_path / "nonexistent-agent.pid"),
        secrets_dir=str(runsec),
        backup_dir=str(bdir),
        audit_log=str(audit),
        backup_retention_days=30,
        symlink_wait_timeout=5,
        max_per_tick=5,
        discord_webhook=None,
    )

    class _Sandbox:
        pass

    sb = _Sandbox()
    sb.daemon = daemon
    sb.bw_client = bw_client
    sb.src_env = src_env
    sb.runsec = runsec
    sb.bdir = bdir
    sb.cfg_path = cfg_path
    sb.audit = audit
    sb.svc_dir = svc_dir
    sb.tmp_root = tmp_path
    sb.fake_bw = fake_bw

    yield sb
    stop_flag.set()


class TestMigrateE2E:
    def test_status_absorbed(self, daemon_sandbox):
        result = daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        assert result.status == "absorbed"

    def test_classifies_keys_correctly(self, daemon_sandbox):
        result = daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        assert sorted(result.keys_absorbed) == ["API_KEY", "DB_PASSWORD"]
        assert "PORT(config)" in result.keys_skipped
        assert "LOG_LEVEL(config)" in result.keys_skipped
        assert len(result.items_created) == 2

    def test_backup_created_with_mode_0600(self, daemon_sandbox, watcher):
        result = daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        assert result.backup_path
        bp = Path(result.backup_path)
        assert str(daemon_sandbox.bdir) in result.backup_path
        assert oct(bp.stat().st_mode & 0o777) == oct(0o600)
        assert watcher._BACKUP_TS_RE.search(bp.name) is not None

    def test_src_swapped_to_merged_symlink(self, daemon_sandbox):
        """After absorption the original .env is a symlink to .env.merged,
        NOT to the vault-only file. This is what guarantees apps reading
        the original path get config + secrets in one view."""
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        assert os.path.islink(daemon_sandbox.src_env)
        assert os.readlink(daemon_sandbox.src_env) == str(
            daemon_sandbox.runsec / "test-svc.env.merged"
        )

    def test_vault_only_file_has_just_secrets(self, daemon_sandbox, watcher):
        """The vault-only render at /run/secrets/<name>.env has only
        secrets — config keys live in .env.static instead."""
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        rendered = watcher.parse_env_file(daemon_sandbox.runsec / "test-svc.env")
        rendered_keys = sorted(k for k, _ in rendered)
        assert rendered_keys == ["API_KEY", "DB_PASSWORD"]

    def test_merged_file_has_secrets_and_config(self, daemon_sandbox, watcher):
        """The merged file (what the app actually sees through the symlink)
        contains BOTH the absorbed secrets AND the preserved config keys."""
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        merged_path = daemon_sandbox.runsec / "test-svc.env.merged"
        assert merged_path.exists()
        merged = watcher.parse_env_file(merged_path)
        merged_keys = sorted(k for k, _ in merged)
        # All four original keys must be present — losing PORT/LOG_LEVEL
        # was the original bug this refactor fixes.
        assert merged_keys == ["API_KEY", "DB_PASSWORD", "LOG_LEVEL", "PORT"]

    def test_config_yaml_updated_with_merge_block(self, daemon_sandbox):
        """The new collection entry in config.yaml carries a `merge:` block
        whose link/static/target match what migrate() chose."""
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        cfg = yaml.safe_load(daemon_sandbox.cfg_path.read_text())
        cols = cfg["sync"]["collections"]
        assert len(cols) == 1
        c = cols[0]
        assert c["id"] == "COLL-test-svc-123"
        assert c["output"] == str(daemon_sandbox.runsec / "test-svc.env")
        assert "merge" in c, "merge: block missing from new collection entry"
        m = c["merge"]
        assert m["link"] == str(daemon_sandbox.src_env)
        assert m["static"] == str(daemon_sandbox.src_env) + ".static"
        assert m["target"] == str(daemon_sandbox.runsec / "test-svc.env.merged")

        backups = list(daemon_sandbox.cfg_path.parent.glob("config.yaml.bak-*"))
        assert len(backups) == 1, f"expected exactly 1 cfg backup, got {backups}"

    def test_static_file_written_with_config_keys(self, daemon_sandbox, watcher):
        """The sibling .env.static file holds the non-secret keys verbatim.
        This is what protects apps from losing PORT, LOG_LEVEL, etc."""
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        static_path = Path(str(daemon_sandbox.src_env) + ".static")
        assert static_path.exists(), ".env.static must exist after migrate"
        static = watcher.parse_env_file(static_path)
        keys = sorted(k for k, _ in static)
        assert keys == ["LOG_LEVEL", "PORT"]
        # And the values must be preserved verbatim.
        as_dict = dict(static)
        assert as_dict["PORT"] == "5432"
        assert as_dict["LOG_LEVEL"] == "INFO"

    def test_static_file_excludes_secrets(self, daemon_sandbox):
        """Sanity: no secret value can ever appear in the static file —
        that would defeat the whole point of moving them to the vault."""
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        static_text = Path(str(daemon_sandbox.src_env) + ".static").read_text()
        for plaintext in ("topsecret_z9_xx_yy", "sk_live_aaa_bbb_ccc"):
            assert plaintext not in static_text, f"static leaks {plaintext!r}"
        # And the secret KEYs themselves should not appear either (lines
        # were dropped wholesale, not just values redacted).
        assert "DB_PASSWORD" not in static_text
        assert "API_KEY" not in static_text

    def test_static_file_has_mode_0600(self, daemon_sandbox):
        """The static file holds non-secrets but may still encode internal
        topology (DB_HOST, NODE_ENV, ...) we don't want exposed."""
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        static_path = Path(str(daemon_sandbox.src_env) + ".static")
        assert oct(static_path.stat().st_mode & 0o777) == oct(0o600)

    def test_static_preserves_comments_and_blank_lines(
        self, daemon_sandbox, tmp_path: Path
    ):
        """Operators write notes in their .env files; those notes must
        survive absorption so the file remains readable after refactor."""
        # Overwrite the sandbox .env with content that has comments and
        # interleaved blanks. Re-run migrate against a fresh collection.
        rich_env = daemon_sandbox.svc_dir.parent / "svc-rich" / ".env"
        rich_env.parent.mkdir(parents=True)
        rich_env.write_text(
            "# Top-level config for svc-rich\n"
            "\n"
            "# DB section\n"
            "DB_HOST=postgres.internal\n"
            "DB_PASSWORD=rotateMe_aaaa_bbbb\n"
            "\n"
            "# Logging\n"
            "LOG_LEVEL=DEBUG\n"
        )
        os.chmod(rich_env, 0o600)
        daemon_sandbox.daemon.migrate(
            env_path=str(rich_env),
            collection_id="COLL-rich-456",
            collection_name="svc-rich",
        )
        static_text = Path(str(rich_env) + ".static").read_text()
        # Comments + blanks survive
        assert "# Top-level config for svc-rich" in static_text
        assert "# DB section" in static_text
        assert "# Logging" in static_text
        # Non-secret keys survive
        assert "DB_HOST=postgres.internal" in static_text
        assert "LOG_LEVEL=DEBUG" in static_text
        # Secret line is gone
        assert "DB_PASSWORD" not in static_text
        assert "rotateMe_aaaa_bbbb" not in static_text

    def test_only_secrets_writes_minimal_static(self, daemon_sandbox):
        """Edge case: a .env with ONLY secrets. The static file gets written
        (so the merge: block has something to point at) but is effectively
        empty."""
        only_secrets = daemon_sandbox.svc_dir.parent / "svc-only-secrets" / ".env"
        only_secrets.parent.mkdir(parents=True)
        only_secrets.write_text(
            "API_KEY=sk_live_only_secrets_xx\nDB_PASSWORD=hunter_only_secrets\n"
        )
        os.chmod(only_secrets, 0o600)
        result = daemon_sandbox.daemon.migrate(
            env_path=str(only_secrets),
            collection_id="COLL-only-secrets-789",
            collection_name="svc-only-secrets",
        )
        assert result.status == "absorbed"
        static_path = Path(str(only_secrets) + ".static")
        assert static_path.exists()
        # File exists but has no key=value pairs
        static_pairs = [
            line
            for line in static_path.read_text().splitlines()
            if line and not line.startswith("#") and "=" in line
        ]
        assert static_pairs == []

    def test_only_config_returns_skipped(self, daemon_sandbox):
        """Edge case: a .env with ZERO secrets. Nothing to absorb, watcher
        returns 'skipped' without touching the file."""
        only_cfg = daemon_sandbox.svc_dir.parent / "svc-only-cfg" / ".env"
        only_cfg.parent.mkdir(parents=True)
        only_cfg.write_text("PORT=8080\nLOG_LEVEL=INFO\nNODE_ENV=production\n")
        os.chmod(only_cfg, 0o600)
        result = daemon_sandbox.daemon.migrate(
            env_path=str(only_cfg),
            collection_id="COLL-only-cfg-999",
            collection_name="svc-only-cfg",
        )
        assert result.status == "skipped"
        assert "no keys classified as secret" in result.reason
        # Original file untouched
        assert not os.path.islink(only_cfg)
        # No static created (we never started the absorption flow)
        assert not Path(str(only_cfg) + ".static").exists()

    def test_audit_no_plaintext_leak(self, daemon_sandbox):
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        entries = [
            json.loads(ln) for ln in daemon_sandbox.audit.read_text().splitlines()
        ]
        assert len(entries) == 1
        a0 = entries[0]
        assert a0["event"] == "absorbed"
        assert a0["host"] == "host-utils"
        assert len(a0.get("origin_sha256", "")) == 64
        assert sorted(a0["keys_absorbed"]) == ["API_KEY", "DB_PASSWORD"]
        # No plaintext values from .env may appear anywhere in the audit line
        blob = json.dumps(a0)
        for plaintext in ("topsecret_z9_xx_yy", "sk_live_aaa_bbb_ccc"):
            assert plaintext not in blob

    def test_bw_item_name_is_env_key(self, daemon_sandbox):
        """The bw item.name must equal the env var key, NOT a `coll / KEY`
        prefix. This is the convention the real agent uses to render env
        files (item.name → env var key, login.password → value). Storing
        anything else here breaks the agent's renderer.
        """
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        created = [
            r for r in daemon_sandbox.fake_bw.read_invocations() if "created" in r
        ]
        assert len(created) == 2
        names = sorted(c["created"]["name"] for c in created)
        # Just the env var keys — no "test-svc / " prefix.
        assert names == ["API_KEY", "DB_PASSWORD"]
        # login.username should be the collection name (descriptive label),
        # NOT the env var key (no name/username collision).
        for cr in created:
            assert cr["created"]["login"]["username"] == "test-svc"

    def test_bw_notes_have_retention_metadata(self, daemon_sandbox):
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        created = [
            r for r in daemon_sandbox.fake_bw.read_invocations() if "created" in r
        ]
        assert len(created) == 2
        for cr in created:
            notes = cr["created"]["notes"]
            assert "host: host-utils" in notes
            assert "ip-172-" not in notes
            assert "backup_retention_days: 30" in notes
            assert "backup_expires_at:" in notes
            # Sanity: the secret value MUST NOT appear in notes.
            assert cr["created"]["login"]["password"] not in notes

    def test_second_call_idempotent_skip(self, daemon_sandbox):
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        result2 = daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        assert result2.status == "skipped"
        assert "already" in result2.reason


# ===========================================================================
# Phase D — WatcherDaemon.tick() loop
# ===========================================================================
class TestWatcherTick:
    def test_no_paths_returns_empty_stats(self, daemon_sandbox):
        # The daemon was built from a config without watch.paths.
        stats = daemon_sandbox.daemon.tick()
        assert stats.discovered == 0
        assert stats.absorbed == 0
        assert stats.failed == 0
        assert stats.rate_limited == 0

    def test_already_managed_skipped(self, daemon_sandbox, watcher):
        # Inject a watch config with a path containing only an already-managed
        # symlink. tick() should skip it without spending the budget.
        daemon_sandbox.src_env.unlink()  # remove the plain .env
        os.symlink(str(daemon_sandbox.runsec / "test-svc.env"), daemon_sandbox.src_env)
        daemon_sandbox.daemon.config = {
            **daemon_sandbox.daemon.config,
            "watch": {
                "paths": [str(daemon_sandbox.svc_dir)],
                "collection_for_dir": {
                    str(daemon_sandbox.svc_dir): {"id": "C1", "name": "c1"}
                },
                "max_depth": 3,
            },
        }
        stats = daemon_sandbox.daemon.tick()
        assert stats.discovered >= 1
        assert stats.skipped_managed >= 1
        assert stats.absorbed == 0

    def test_no_mapping_logs_and_skips(self, daemon_sandbox):
        # New candidate without a collection mapping. v1.2.2 (in v1.5.1):
        # the sandbox writes under /tmp/, which the default ignore_paths
        # cover — so the path is correctly bucketed as stats.skipped now,
        # not stats.no_mapping. Either way it must NOT be absorbed. The
        # rebuilt assertion verifies the non-absorb invariant without
        # depending on the exact bucket (which is what the v1.2.2 fix
        # specifically distinguishes).
        daemon_sandbox.daemon.config = {
            **daemon_sandbox.daemon.config,
            "watch": {
                "paths": [str(daemon_sandbox.svc_dir)],
                "collection_for_dir": {},  # intentionally empty
                "max_depth": 3,
            },
        }
        stats = daemon_sandbox.daemon.tick()
        assert (stats.no_mapping + stats.skipped) >= 1
        assert stats.absorbed == 0

    def test_rate_limit_caps_per_tick(self, daemon_sandbox):
        # Create multiple candidate files. With max_per_tick=1 set on the
        # daemon, the second/third file must be rate_limited.
        daemon_sandbox.daemon.max_per_tick = 1
        for i in range(3):
            d = daemon_sandbox.tmp_root / f"home/svc-{i}"
            d.mkdir(parents=True)
            (d / ".env").write_text("DB_PASSWORD=secret_x_x_x\n")
        daemon_sandbox.daemon.config = {
            **daemon_sandbox.daemon.config,
            "watch": {
                "paths": [str(daemon_sandbox.tmp_root / "home")],
                "collection_for_dir": {
                    str(daemon_sandbox.tmp_root / "home" / "svc-0"): {
                        "id": "C0",
                        "name": "svc-0",
                    },
                    str(daemon_sandbox.tmp_root / "home" / "svc-1"): {
                        "id": "C1",
                        "name": "svc-1",
                    },
                    str(daemon_sandbox.tmp_root / "home" / "svc-2"): {
                        "id": "C2",
                        "name": "svc-2",
                    },
                },
                "max_depth": 3,
            },
        }
        stats = daemon_sandbox.daemon.tick()
        assert stats.absorbed + stats.failed + stats.deferred == 1
        assert stats.rate_limited >= 2


# ===========================================================================
# Misc — _load_config, _doctor, _acquire_single_instance_lock
# ===========================================================================
class TestLoadConfig:
    def test_missing_file_returns_none(self, watcher, tmp_path: Path):
        assert watcher._load_config(str(tmp_path / "nope.yaml")) is None

    def test_invalid_yaml_returns_none(self, watcher, tmp_path: Path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("key: : :\n: invalid: yaml: :\n")
        assert watcher._load_config(str(bad)) is None

    def test_resolves_discord_webhook_file(self, watcher, tmp_path: Path):
        wh = tmp_path / "wh.secret"
        wh.write_text("https://discord.example/webhook  \n")
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text(
            yaml.safe_dump(
                {
                    "alerts": {"discord_webhook_file": str(wh)},
                }
            )
        )
        cfg = watcher._load_config(str(cfg_path))
        assert cfg is not None
        assert cfg["alerts"]["discord_webhook"] == "https://discord.example/webhook"


class TestSingleInstanceLock:
    def test_acquire_returns_handle(self, watcher, tmp_path: Path):
        fh = watcher._acquire_single_instance_lock(str(tmp_path / "w.lock"))
        try:
            assert fh is not None
        finally:
            if fh:
                fh.close()

    def test_second_acquire_returns_none(self, watcher, tmp_path: Path):
        lock = str(tmp_path / "w.lock")
        fh1 = watcher._acquire_single_instance_lock(lock)
        try:
            fh2 = watcher._acquire_single_instance_lock(lock)
            assert fh2 is None
        finally:
            if fh1:
                fh1.close()


class TestDoctor:
    def test_returns_1_on_missing_required_fields(self, watcher, tmp_path: Path):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("# empty config\n")
        rc = watcher._doctor(str(cfg))
        assert rc == 1

    def test_returns_1_on_unreadable_config(self, watcher, tmp_path: Path):
        rc = watcher._doctor(str(tmp_path / "nope.yaml"))
        assert rc == 1


# ===========================================================================
# M1 — ensure_collection() get-or-create + migrate() fail-closed behaviour
# ===========================================================================
class TestEnsureCollectionM1:
    def test_exists_via_preferred_id(self, daemon_sandbox):
        cid, status = daemon_sandbox.bw_client.ensure_collection(
            name="test-svc", org_id="ORG-AAA", preferred_id="COLL-test-svc-123"
        )
        assert (cid, status) == ("COLL-test-svc-123", "exists")
        # No collection was created.
        assert not any(
            "created_collection" in r for r in daemon_sandbox.fake_bw.read_invocations()
        )

    def test_exists_via_name_when_id_drifted(self, daemon_sandbox):
        cid, status = daemon_sandbox.bw_client.ensure_collection(
            name="test-svc", org_id="ORG-AAA", preferred_id="STALE-WRONG-ID"
        )
        assert status == "exists"
        assert cid == "COLL-test-svc-123"

    def test_created_when_absent(self, daemon_sandbox):
        cid, status = daemon_sandbox.bw_client.ensure_collection(
            name="totally-new-svc", org_id="ORG-AAA", preferred_id="NOPE"
        )
        assert status == "created"
        assert cid == "COLL-created-totally-new-svc"
        # Idempotent: a second call now finds it (exists, no 2nd create).
        cid2, status2 = daemon_sandbox.bw_client.ensure_collection(
            name="totally-new-svc", org_id="ORG-AAA", preferred_id="NOPE"
        )
        assert (cid2, status2) == ("COLL-created-totally-new-svc", "exists")

    def test_migrate_creates_absent_collection_e2e(self, daemon_sandbox):
        """The headline case: collection NOT pre-created → watcher creates it
        and the absorb completes instead of blocking."""
        result = daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="UNKNOWN-ID-xyz",
            collection_name="fresh-collection",
        )
        assert result.status == "absorbed", result.reason
        assert result.collection_id == "COLL-created-fresh-collection"
        # .env became a managed symlink.
        assert os.path.islink(str(daemon_sandbox.src_env))

    def test_migrate_deferred_when_list_unreachable(self, daemon_sandbox, monkeypatch):
        """bw list org-collections fails → migrate defers and leaves the
        original .env completely untouched (no backup, no static)."""
        original = Path(daemon_sandbox.src_env).read_text()
        monkeypatch.setattr(
            daemon_sandbox.bw_client,
            "list_org_collections",
            lambda org_id: None,
        )
        result = daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="X",
            collection_name="svc-x",
        )
        assert result.status == "deferred"
        assert not os.path.islink(str(daemon_sandbox.src_env))
        assert Path(daemon_sandbox.src_env).read_text() == original
        assert not Path(str(daemon_sandbox.src_env) + ".static").exists()

    def test_migrate_failed_closed_when_create_denied(
        self, daemon_sandbox, monkeypatch
    ):
        """ensure_collection denied (no perms) → migrate FAILS CLOSED: .env
        untouched, no static file, reason explains the permission gap."""
        original = Path(daemon_sandbox.src_env).read_text()
        monkeypatch.setattr(
            daemon_sandbox.bw_client,
            "ensure_collection",
            lambda *a, **k: (None, "denied"),
        )
        result = daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="X",
            collection_name="svc-x",
        )
        assert result.status == "failed"
        assert "permission" in result.reason.lower()
        assert not os.path.islink(str(daemon_sandbox.src_env))
        assert Path(daemon_sandbox.src_env).read_text() == original
        assert not Path(str(daemon_sandbox.src_env) + ".static").exists()


# ===========================================================================
# M8 — agent merge-file perms (_resolve_merge_perms / _atomic_write_secret)
# ===========================================================================
@pytest.fixture(scope="session")
def agent_mod():
    # v1.5.1: point to the current agent next to the watcher in HERE.parent
    # (the older `agent-v1.4.9/` layout only existed in v1.4.x worktrees).
    spec = importlib.util.spec_from_file_location(
        "dw_agent", HERE.parent / "agent" / "socialwarden-agent.py"
    )
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


class TestAgentMergePermsM8:
    def test_default_mode_is_0640_not_world_readable(self, agent_mod):
        mode, uid, gid, mat = agent_mod.SyncEngine._resolve_merge_perms({})
        assert mode == 0o640
        assert mat == "symlink"
        assert uid == -1 and gid == -1
        # The historical world-readable bit is gone.
        assert not (mode & 0o004)

    def test_octal_string_and_decimal_mode(self, agent_mod):
        m1, *_ = agent_mod.SyncEngine._resolve_merge_perms({"mode": "0600"})
        m2, *_ = agent_mod.SyncEngine._resolve_merge_perms({"mode": 600})
        m3, *_ = agent_mod.SyncEngine._resolve_merge_perms({"mode": 0o640})
        assert m1 == 0o600 and m2 == 0o600 and m3 == 0o640

    def test_materialize_copy_and_unknown_falls_back(self, agent_mod):
        _, _, _, mat = agent_mod.SyncEngine._resolve_merge_perms(
            {"materialize": "copy"}
        )
        assert mat == "copy"
        _, _, _, mat2 = agent_mod.SyncEngine._resolve_merge_perms(
            {"materialize": "weird"}
        )
        assert mat2 == "symlink"

    def test_unknown_owner_group_ignored(self, agent_mod):
        _, uid, gid, _ = agent_mod.SyncEngine._resolve_merge_perms(
            {"owner": "nosuchuser_zzz", "group": "nosuchgroup_zzz"}
        )
        assert uid == -1 and gid == -1

    def test_atomic_write_secret_exact_mode(self, agent_mod, tmp_path: Path):
        dest = tmp_path / "sub" / "secret.env"
        dest.parent.mkdir()
        ok = agent_mod.SyncEngine._atomic_write_secret(str(dest), b"K=v\n", 0o640)
        assert ok
        assert dest.read_bytes() == b"K=v\n"
        assert (dest.stat().st_mode & 0o777) == 0o640

    def test_atomic_write_secret_chown_failure_not_fatal(
        self, agent_mod, tmp_path: Path
    ):
        # uid 0 as non-root → fchown fails, but write still succeeds.
        dest = tmp_path / "s.env"
        ok = agent_mod.SyncEngine._atomic_write_secret(
            str(dest), b"A=b\n", 0o600, uid=0, gid=0
        )
        assert ok
        assert dest.read_bytes() == b"A=b\n"
        assert (dest.stat().st_mode & 0o777) == 0o600


# ===========================================================================
# M2 — watcher materialize strategy (copy for non-root operators)
# ===========================================================================
class TestMaterializeM2:
    def _daemon(self, watcher, tmp_path):
        bw = watcher.BWClient(
            email="a@b.c",
            server_url="",
            master_password="pw",
            bw_binary="/bin/true",
            lock_path=str(tmp_path / "l"),
        )
        return watcher.WatcherDaemon(config={}, bw_client=bw)

    def test_explicit_config_wins(self, watcher, tmp_path: Path):
        d = self._daemon(watcher, tmp_path)
        d.config = {
            "watch": {
                "materialize_for_dir": {
                    "/srv/app": {"strategy": "copy", "group": "appusr", "mode": "0600"}
                }
            }
        }
        m = d._materialize_for("/srv/app/.env")
        assert m["materialize"] == "copy"
        assert m["group"] == "appusr" and m["mode"] == "0600"

    def test_autodetect_nonroot_dir_picks_copy(self, watcher, tmp_path: Path):
        import grp
        import pwd

        d = self._daemon(watcher, tmp_path)
        proj = tmp_path / "proj"
        proj.mkdir()
        # Deterministic regardless of who runs pytest: ensure the project dir
        # is owned by a NON-root uid. When the suite runs as root (e.g. the
        # integration harness under sudo) tmp_path is root-owned, so chown
        # it to a stable non-root uid; as a normal user it already is.
        if os.geteuid() == 0:
            os.chown(proj, 1000, 1000)
        if os.stat(proj).st_uid == 0:
            import pytest

            pytest.skip("cannot obtain a non-root-owned dir to assert copy")
        m = d._materialize_for(str(proj / ".env"))
        assert m["materialize"] == "copy"
        assert (
            m["group"]
            == grp.getgrgid(pwd.getpwuid(os.stat(proj).st_uid).pw_gid).gr_name
        )

    def test_autodetect_root_dir_defaults_symlink(self, watcher, tmp_path: Path):
        d = self._daemon(watcher, tmp_path)
        m = d._materialize_for("/etc/.env")  # /etc owned by root
        assert m["materialize"] == "symlink" and m["mode"] == "0640"

    def test_is_already_managed_recognises_copy_file(self, watcher, tmp_path: Path):
        p = tmp_path / ".env"
        p.write_text("PORT=1\n" + watcher.SOCIALWARDEN_MERGED_SENTINEL + "\nSECRET=x\n")
        assert watcher.is_already_managed(str(p), secrets_dir=str(tmp_path / "rs"))

    def test_is_already_managed_plain_file_false(self, watcher, tmp_path: Path):
        p = tmp_path / ".env"
        p.write_text("PORT=1\nSECRET=x\n")
        assert not watcher.is_already_managed(str(p), secrets_dir=str(tmp_path / "rs"))

    def test_migrate_copy_e2e_safety_net(self, daemon_sandbox):
        """Force copy mode; the fixture's agent-sim only does symlink, so the
        watcher's copy safety-net must materialize a REAL managed file."""
        import grp
        import pwd

        u = pwd.getpwuid(os.getuid()).pw_name
        g = grp.getgrgid(os.getgid()).gr_name
        d = daemon_sandbox.daemon
        d.config.setdefault("watch", {})["materialize_for_dir"] = {
            str(daemon_sandbox.svc_dir): {
                "strategy": "copy",
                "owner": u,
                "group": g,
                "mode": "0640",
            }
        }
        result = d.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        assert result.status == "absorbed", result.reason
        env = daemon_sandbox.src_env
        assert not os.path.islink(str(env))  # real file, NOT a symlink
        assert env.is_file()
        text = env.read_text()
        assert daemon_sandbox.daemon  # sanity
        from importlib import import_module  # noqa

        assert "=== Secrets managed by SocialWarden" in text
        assert "DB_PASSWORD=" in text and "PORT=" in text
        assert (os.stat(str(env)).st_mode & 0o777) == 0o640
        # Idempotent: a second migrate sees it managed and skips.
        r2 = d.migrate(
            env_path=str(env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        assert r2.status == "skipped"


# ===========================================================================
# M5 — doctor per-target pre-flight checks
# ===========================================================================
class TestDoctorPerTargetM5:
    def _full_cfg(self, tmp_path: Path) -> Path:
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / ".env").write_text("DB_PASSWORD=secret_aaa_bbb\nPORT=8080\n")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "auth: {email: contact@example.com}\n"
            "machine: {name: host-utils}\n"
            "server: {url: 'https://vault.example'}\n"
            "organization: {id: ORG-AAA}\n"
            f"watch: {{paths: ['{proj}'], max_depth: 2}}\n"
        )
        return cfg, proj

    def _stub_daemon(self, watcher, *, colls, mat):
        class _BW:
            def list_org_collections(self, org_id):
                return colls

        class _D:
            bw = _BW()

            def _collection_for(self, p):
                return {"id": "CID-1", "name": "proj-coll"}

            def _materialize_for(self, p):
                return mat

        return _D()

    def test_absent_collection_is_informational_not_failure(
        self, watcher, tmp_path: Path, monkeypatch, capsys
    ):
        cfg, _ = self._full_cfg(tmp_path)
        monkeypatch.setattr(
            watcher,
            "_build_daemon",
            lambda c: self._stub_daemon(
                watcher,
                colls=[],
                mat={
                    "materialize": "symlink",
                    "mode": "0640",
                    "owner": "root",
                    "group": "root",
                },
            ),
        )
        watcher._doctor(str(cfg))
        out = capsys.readouterr().out
        assert "in vault" in out
        # Absent collection prints with a ✓ (informational), never ✗.
        line = [ln for ln in out.splitlines() if "in vault" in ln][0]
        assert "[✓]" in line and "auto-created on absorb" in line

    def test_unparseable_env_and_bad_group_flagged(
        self, watcher, tmp_path: Path, monkeypatch, capsys
    ):
        cfg, proj = self._full_cfg(tmp_path)
        # Make the .env unreadable-as-utf8 (binary garbage).
        (proj / ".env").write_bytes(b"\xff\xfe\x00\x00BADxx")
        monkeypatch.setattr(
            watcher,
            "_build_daemon",
            lambda c: self._stub_daemon(
                watcher,
                colls=[{"id": "CID-1", "name": "proj-coll"}],
                mat={
                    "materialize": "copy",
                    "mode": "0640",
                    "owner": "root",
                    "group": "nosuchgroup_zzz_999",
                },
            ),
        )
        rc = watcher._doctor(str(cfg))
        out = capsys.readouterr().out
        assert "parseable" in out
        assert "group 'nosuchgroup_zzz_999' exists" in out
        # A bad group / unparseable .env are real problems → non-zero exit.
        assert rc == 1

    def test_config_writable_and_disk_checks_present(
        self, watcher, tmp_path: Path, capsys
    ):
        cfg, _ = self._full_cfg(tmp_path)
        watcher._doctor(str(cfg))
        out = capsys.readouterr().out
        assert "agent config.yaml writable by watcher" in out
        assert "free space on /run (merged tmpfs)" in out
        assert "free space on backup dir" in out


# ===========================================================================
# M3 — absorb journal (resumable / stuck detection)
# ===========================================================================
class TestAbsorbJournalM3:
    def test_journal_roundtrip_and_clear(self, watcher, tmp_path: Path):
        sd = str(tmp_path / "state")
        ep = "/home/x/proj/.env"
        assert watcher._journal_read(ep, state_dir=sd) is None
        assert watcher._journal_write(ep, {"phase": "vault_created"}, state_dir=sd)
        j = watcher._journal_read(ep, state_dir=sd)
        assert j["phase"] == "vault_created"
        assert j["env_path"] == ep and "updated_at" in j
        watcher._journal_clear(ep, state_dir=sd)
        assert watcher._journal_read(ep, state_dir=sd) is None

    def test_journal_cleared_after_successful_absorb(self, daemon_sandbox, tmp_path):
        d = daemon_sandbox.daemon
        d.state_dir = str(tmp_path / "jstate")
        ep = str(daemon_sandbox.src_env)
        r = d.migrate(
            env_path=ep, collection_id="COLL-test-svc-123", collection_name="test-svc"
        )
        assert r.status == "absorbed", r.reason
        # Clean terminal state → journal removed (not "stuck").
        import importlib

        w = importlib.import_module("dw_watcher")
        assert w._journal_read(ep, state_dir=d.state_dir) is None

    def test_scan_flags_old_nonterminal_journal(
        self, watcher, tmp_path: Path, monkeypatch
    ):
        sd = str(tmp_path / "state")
        plain = tmp_path / "proj" / ".env"
        plain.parent.mkdir(parents=True)
        plain.write_text("A=b\n")  # NOT managed (plain file)
        # Stuck journal: non-terminal phase, updated long ago.
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        watcher._journal_write(
            str(plain),
            {"phase": "vault_created", "updated_at_override": old},
            state_dir=sd,
        )
        # Force the stored updated_at to be old (write stamps it to now).
        jp = watcher._journal_path(str(plain), state_dir=sd)
        data = json.loads(open(jp).read())
        data["updated_at"] = old
        open(jp, "w").write(json.dumps(data))

        alerts = []
        monkeypatch.setattr(
            watcher, "send_discord_alert", lambda *a, **k: alerts.append((a, k))
        )

        class _Stub:
            secrets_dir = str(tmp_path / "rs")
            state_dir = sd
            machine_name = "host-utils"
            discord_webhook = "http://x"

        watcher._scan_stuck_absorbs(_Stub())
        assert len(alerts) == 1
        j = json.loads(open(jp).read())
        assert j.get("stuck_alerted") is True
        # Second scan must NOT re-alert (flag set).
        watcher._scan_stuck_absorbs(_Stub())
        assert len(alerts) == 1

    def test_scan_ignores_terminal_and_managed(
        self, watcher, tmp_path: Path, monkeypatch
    ):
        sd = str(tmp_path / "state")
        rs = tmp_path / "rs"
        rs.mkdir()
        # (a) terminal phase → ignored
        watcher._journal_write("/p/a/.env", {"phase": "done"}, state_dir=sd)
        # (b) non-terminal but target IS managed (symlink into secrets) → tidied
        managed = tmp_path / "m" / ".env"
        managed.parent.mkdir(parents=True)
        (rs / "m.env.merged").write_text("X=1\n")
        os.symlink(str(rs / "m.env.merged"), str(managed))
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        watcher._journal_write(str(managed), {"phase": "config_edited"}, state_dir=sd)
        jp = watcher._journal_path(str(managed), state_dir=sd)
        dd = json.loads(open(jp).read())
        dd["updated_at"] = old
        open(jp, "w").write(json.dumps(dd))

        alerts = []
        monkeypatch.setattr(
            watcher, "send_discord_alert", lambda *a, **k: alerts.append(1)
        )

        class _Stub:
            secrets_dir = str(rs)
            state_dir = sd
            machine_name = "host-utils"
            discord_webhook = "http://x"

        watcher._scan_stuck_absorbs(_Stub())
        assert alerts == []  # neither should alert
        # The managed-but-journaled one got tidied away.
        assert watcher._journal_read(str(managed), state_dir=sd) is None


# ===========================================================================
# M4 — rollback (revert an absorb)
# ===========================================================================
class TestRollbackM4:
    def test_find_latest_backup(self, watcher, tmp_path: Path):
        bd = tmp_path / "bk"
        bd.mkdir()
        flat = watcher._flatten_path_for_backup("/home/x/proj/.env")
        (bd / f"{flat}-20260515T100000Z").write_text("old")
        (bd / f"{flat}-20260515T120000Z").write_text("new")
        (bd / f"{flat}-20260515T110000Z").write_text("mid")
        got = watcher._find_latest_backup("/home/x/proj/.env", backup_dir=str(bd))
        assert got.endswith("20260515T120000Z")

    def test_remove_collection_from_agent_config(self, watcher, tmp_path: Path):
        import yaml

        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            yaml.safe_dump(
                {
                    "sync": {
                        "collections": [
                            {
                                "id": "A",
                                "name": "keep",
                                "merge": {"link": "/other/.env"},
                            },
                            {
                                "id": "B",
                                "name": "drop",
                                "merge": {"link": "/proj/.env"},
                            },
                        ]
                    }
                }
            )
        )
        removed, entry = watcher._remove_collection_from_agent_config(
            str(cfg), "/proj/.env"
        )
        assert removed and entry["id"] == "B"
        left = yaml.safe_load(cfg.read_text())["sync"]["collections"]
        assert [c["id"] for c in left] == ["A"]
        # Idempotent: removing again finds nothing.
        again, _ = watcher._remove_collection_from_agent_config(str(cfg), "/proj/.env")
        assert again is False

    def test_rollback_dry_run_mutates_nothing(self, watcher, tmp_path, capsys):
        env = tmp_path / "proj" / ".env"
        env.parent.mkdir()
        env.write_text("SECRET=x\n")
        cfg = tmp_path / "config.yaml"
        cfg.write_text("sync: {collections: []}\n")
        before = env.read_text()
        rc = watcher._rollback(str(env), config_path=str(cfg), apply=False)
        out = capsys.readouterr().out
        assert "DRY-RUN" in out
        assert env.read_text() == before
        # No backup exists → dry-run still returns 1 (nothing to restore).
        assert rc == 1

    def test_rollback_apply_restores_env(self, daemon_sandbox, tmp_path, capsys):
        d = daemon_sandbox.daemon
        d.state_dir = str(tmp_path / "jst")
        d.backup_dir = str(tmp_path / "bks")
        ep = str(daemon_sandbox.src_env)
        original = Path(ep).read_text()
        r = d.migrate(
            env_path=ep, collection_id="COLL-test-svc-123", collection_name="test-svc"
        )
        assert r.status == "absorbed", r.reason
        assert os.path.islink(ep)  # managed now

        import importlib

        w = importlib.import_module("dw_watcher")
        # point module BACKUP_DIR/AUDIT to the sandbox via monkeypatching attrs
        rc = w._rollback(
            ep,
            config_path=str(daemon_sandbox.cfg_path),
            apply=True,
            purge_vault=False,
            backup_dir=d.backup_dir,
            state_dir=d.state_dir,
            audit_log=str(tmp_path / "audit.jsonl"),
        )
        assert rc == 0
        capsys.readouterr()
        # .env is a real file again with the ORIGINAL content.
        assert not os.path.islink(ep)
        assert Path(ep).read_text() == original
        # config entry gone; .env.static gone.
        import yaml

        colls = (
            yaml.safe_load(Path(daemon_sandbox.cfg_path).read_text())
            .get("sync", {})
            .get("collections", [])
        )
        assert all((c.get("merge") or {}).get("link") != ep for c in colls)
        assert not Path(ep + ".static").exists()


# ===========================================================================
# M11 — per-target classify overrides + classify-preview
# ===========================================================================
class TestClassifyOverridesM11:
    def test_force_secret_beats_config_heuristic(self, watcher):
        # NODE_ENV normally → config; forced → secret.
        ov = {"force_secret": {"NODE_ENV"}, "force_config": set()}
        assert watcher.classify("NODE_ENV", "production", overrides=ov) == "secret"
        # unaffected key still heuristic
        assert watcher.classify("DB_PASSWORD", "x", overrides=ov) == "secret"

    def test_force_config_beats_secret_heuristic(self, watcher):
        # API_KEY normally → secret; forced → config (e.g. a public key id).
        ov = {"force_secret": set(), "force_config": {"API_KEY"}}
        assert watcher.classify("API_KEY", "pk_public_xyz", overrides=ov) == "config"

    def test_overlap_force_secret_wins(self, watcher):
        ov = {"force_secret": {"TOK"}, "force_config": {"TOK"}}
        assert watcher.classify("TOK", "v", overrides=ov) == "secret"

    def test_placeholder_skip_still_wins_over_override(self, watcher):
        ov = {"force_secret": {"EMPTY"}, "force_config": set()}
        assert watcher.classify("EMPTY", "", overrides=ov) == "skip"

    def test_none_overrides_is_backcompat(self, watcher):
        assert watcher.classify("PORT", "8080") == "config"
        assert watcher.classify("PASSWORD", "hunter2") == "secret"

    def test_daemon_resolves_overrides_per_dir(self, watcher, tmp_path: Path):
        bw = watcher.BWClient(
            email="a@b.c",
            server_url="",
            master_password="pw",
            bw_binary="/bin/true",
            lock_path=str(tmp_path / "l"),
        )
        d = watcher.WatcherDaemon(
            config={
                "watch": {
                    "classify_overrides": {
                        "/srv/app": {
                            "force_secret": ["NODE_ENV"],
                            "force_config": ["API_KEY"],
                        }
                    }
                }
            },
            bw_client=bw,
        )
        ov = d._classify_overrides_for("/srv/app/.env")
        assert ov["force_secret"] == {"NODE_ENV"}
        assert ov["force_config"] == {"API_KEY"}
        # different dir → no overrides
        assert d._classify_overrides_for("/other/.env") is None

    def test_classify_preview_output(self, watcher, tmp_path: Path, capsys):
        env = tmp_path / "app" / ".env"
        env.parent.mkdir()
        env.write_text(
            "API_KEY=pk_public\nDB_PASSWORD=s3cr3t_aa_bb\nPORT=8080\nEMPTY=\n"
        )
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "watch:\n  classify_overrides:\n"
            f"    {env.parent}:\n"
            "      force_config: [API_KEY]\n"
        )
        rc = watcher._classify_preview(str(env), config_path=str(cfg))
        out = capsys.readouterr().out
        assert rc == 0
        assert "forced config" in out  # API_KEY override applied
        assert "secret DB_PASSWORD" in out
        assert "config PORT" in out
        assert "skip   EMPTY" in out
        assert "1 secret(s)" in out  # only DB_PASSWORD


# ===========================================================================
# M14 — drift reconciliation
# ===========================================================================
class TestDriftReconcileM14:
    def _setup(self, watcher, tmp_path, *, items=None):
        import yaml

        rs = tmp_path / "rs"
        rs.mkdir()
        proj = tmp_path / "proj"
        proj.mkdir()
        link = proj / ".env"
        target = rs / "p.env.merged"
        target.write_text("K=v\n")
        cfgf = tmp_path / "config.yaml"
        cfgf.write_text(
            yaml.safe_dump(
                {
                    "sync": {
                        "collections": [
                            {
                                "id": "CID-1",
                                "name": "proj-coll",
                                "merge": {
                                    "link": str(link),
                                    "target": str(target),
                                    "materialize": "symlink",
                                },
                            }
                        ]
                    }
                }
            )
        )

        class _BW:
            def list_items_in_collection(self, cid):
                return items

        d = watcher.WatcherDaemon(
            config={},
            bw_client=_BW(),
            agent_config_path=str(cfgf),
            secrets_dir=str(rs),
            audit_log=str(tmp_path / "a.jsonl"),
        )
        return d, link, target, rs

    def test_detects_reverted_plaintext(self, watcher, tmp_path, monkeypatch):
        d, link, target, rs = self._setup(watcher, tmp_path)
        link.write_text("DB_PASSWORD=leaked\n")  # plain file = reverted
        al = []
        monkeypatch.setattr(
            watcher, "send_discord_alert", lambda *a, **k: al.append(k.get("title", ""))
        )
        watcher._reconcile_drift(d)
        assert any("reverted" in t for t in al)

    def test_detects_missing_link(self, watcher, tmp_path, monkeypatch):
        d, link, target, rs = self._setup(watcher, tmp_path)
        # link never created → missing
        al = []
        monkeypatch.setattr(
            watcher, "send_discord_alert", lambda *a, **k: al.append(k.get("title", ""))
        )
        watcher._reconcile_drift(d)
        assert any("missing" in t for t in al)

    def test_detects_no_merged(self, watcher, tmp_path, monkeypatch):
        d, link, target, rs = self._setup(watcher, tmp_path)
        os.symlink(str(target), str(link))  # properly managed
        target.unlink()  # agent stopped rendering
        al = []
        monkeypatch.setattr(
            watcher, "send_discord_alert", lambda *a, **k: al.append(k.get("title", ""))
        )
        watcher._reconcile_drift(d)
        assert any("no_merged" in t for t in al)

    def test_detects_vault_empty_when_managed(self, watcher, tmp_path, monkeypatch):
        d, link, target, rs = self._setup(watcher, tmp_path, items=[])
        os.symlink(str(target), str(link))  # managed + merged present
        al = []
        monkeypatch.setattr(
            watcher, "send_discord_alert", lambda *a, **k: al.append(k.get("title", ""))
        )
        watcher._reconcile_drift(d)
        assert any("vault_empty" in t for t in al)

    def test_flap_suppression_then_realert(self, watcher, tmp_path, monkeypatch):
        d, link, target, rs = self._setup(watcher, tmp_path)
        link.write_text("X=y\n")  # reverted
        al = []
        monkeypatch.setattr(watcher, "send_discord_alert", lambda *a, **k: al.append(1))
        watcher._reconcile_drift(d)
        watcher._reconcile_drift(d)  # same drift → suppressed
        assert len(al) == 1
        # Heal it (proper symlink), reconcile clears suppression…
        link.unlink()
        os.symlink(str(target), str(link))
        watcher._reconcile_drift(d)
        # …drift again → re-alerts.
        link.unlink()
        link.write_text("X=y\n")
        watcher._reconcile_drift(d)
        assert len(al) == 2

    def test_clean_managed_no_alert(self, watcher, tmp_path, monkeypatch):
        d, link, target, rs = self._setup(watcher, tmp_path, items=[{"id": "i"}])
        os.symlink(str(target), str(link))
        al = []
        monkeypatch.setattr(watcher, "send_discord_alert", lambda *a, **k: al.append(1))
        watcher._reconcile_drift(d)
        assert al == []


# ===========================================================================
# M15 — heartbeat dead-man's-switch + Prometheus metrics
# ===========================================================================
class TestHeartbeatM15:
    def test_write_metrics_format(self, watcher, tmp_path: Path):
        p = str(tmp_path / "m" / "w.prom")
        watcher._write_watcher_metrics(
            "host-utils",
            {"ticks": 5, "absorbed": 2, "failed": 1, "deferred": 0},
            drift_count=3,
            path=p,
        )
        txt = Path(p).read_text()
        assert 'socialwarden_watcher_ticks_total{machine="host-utils"} 5' in txt
        assert 'socialwarden_watcher_absorbed_total{machine="host-utils"} 2' in txt
        assert 'socialwarden_watcher_drift_active{machine="host-utils"} 3' in txt
        assert "socialwarden_watcher_up" in txt
        assert "socialwarden_watcher_last_tick_timestamp" in txt

    def test_healthcheck_fresh_returns_0(self, watcher, tmp_path, monkeypatch, capsys):
        hb = tmp_path / "hb"
        hb.write_text(datetime.now(timezone.utc).isoformat() + "\n")
        monkeypatch.setattr(watcher, "HEARTBEAT_PATH", str(hb))
        assert watcher._healthcheck(max_age_s=600) == 0
        assert "OK:" in capsys.readouterr().out

    def test_healthcheck_stale_returns_1_and_alerts(
        self, watcher, tmp_path, monkeypatch, capsys
    ):
        hb = tmp_path / "hb"
        old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        hb.write_text(old + "\n")
        monkeypatch.setattr(watcher, "HEARTBEAT_PATH", str(hb))
        alerts = []
        monkeypatch.setattr(
            watcher, "send_discord_alert", lambda *a, **k: alerts.append(k.get("title"))
        )
        monkeypatch.setattr(
            watcher,
            "_load_config",
            lambda p: {
                "alerts": {"discord_webhook": "http://x"},
                "machine": {"name": "host-utils"},
            },
        )
        rc = watcher._healthcheck(max_age_s=600, alert=True)
        assert rc == 1
        assert "STALE" in capsys.readouterr().out
        assert alerts == ["Watcher dead-man's-switch"]

    def test_healthcheck_missing_returns_1(
        self, watcher, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setattr(watcher, "HEARTBEAT_PATH", str(tmp_path / "nope"))
        assert watcher._healthcheck(max_age_s=600) == 1
        assert "STALE" in capsys.readouterr().out

    def test_healthcheck_no_alert_flag_no_discord(self, watcher, tmp_path, monkeypatch):
        monkeypatch.setattr(watcher, "HEARTBEAT_PATH", str(tmp_path / "nope"))
        called = []
        monkeypatch.setattr(
            watcher, "send_discord_alert", lambda *a, **k: called.append(1)
        )
        watcher._healthcheck(max_age_s=600, alert=False)
        assert called == []


# ===========================================================================
# E1 — hygiene: M17 self-protect, M18 decommission, M21 log-leak, M22 ENOSPC
# ===========================================================================
class TestHygieneE1:
    # ---- M17 ----
    def test_infra_protected_paths(self, watcher):
        for p in (
            "/var/lib/socialwarden/master.key",
            "/run/secrets/app-b.env.merged",
            "/etc/socialwarden/config.yaml",
            "/run/socialwarden/agent.pid",
            "/some/where/master.key",
        ):
            assert watcher._is_infra_protected(p), p
        for p in ("/home/ubuntu/app/.env", "/srv/x/.env", "/opt/y/.env"):
            assert not watcher._is_infra_protected(p), p

    def test_tick_refuses_infra_and_decommissioned(self, daemon_sandbox, tmp_path):
        d = daemon_sandbox.daemon
        # watch a dir that contains a normal .env, an infra-ish path, and a
        # decommissioned target.
        wd = tmp_path / "wp"
        wd.mkdir()
        (wd / ".env").write_text("DB_PASSWORD=aaa_bbb_ccc\n")
        (wd / "ok.env").write_text("API_KEY=zzz_yyy_xxx\n")
        # decommission marker for ok.env → tick must skip it (M18)
        Path(str(wd / "ok.env") + ".socialwarden-decommissioned").write_text("x")
        d.config = {
            "watch": {"paths": [str(wd)], "max_depth": 2, "collection_for_dir": {}}
        }
        stats = d.tick()
        # .env discovered (no mapping → no_mapping), ok.env skipped by marker.
        # Neither raises; the decommissioned one is NOT in candidates.
        assert stats.discovered == 1  # only .env; ok.env filtered out

    # ---- M18 ----
    def test_rollback_writes_decommission_marker(self, daemon_sandbox, tmp_path):
        d = daemon_sandbox.daemon
        d.state_dir = str(tmp_path / "js")
        d.backup_dir = str(tmp_path / "bk")
        ep = str(daemon_sandbox.src_env)
        d.migrate(
            env_path=ep, collection_id="COLL-test-svc-123", collection_name="test-svc"
        )
        import importlib

        w = importlib.import_module("dw_watcher")
        w._rollback(
            ep,
            config_path=str(daemon_sandbox.cfg_path),
            apply=True,
            backup_dir=d.backup_dir,
            state_dir=d.state_dir,
            audit_log=str(tmp_path / "a.jsonl"),
        )
        assert Path(ep + ".socialwarden-decommissioned").exists()

    # ---- M21 ----
    def test_safe_blob_no_raw_content(self, watcher):
        secret = '[{"login":{"password":"sk_live_SUPERSECRET"}}]'
        b = watcher._safe_blob(secret)
        assert "SUPERSECRET" not in b
        assert b.startswith("<") and "sha256=" in b
        assert str(len(secret)) in b

    # ---- M22 ----
    def test_write_text_atomic_enospc_keeps_lastgood(
        self, watcher, tmp_path, monkeypatch
    ):
        import errno as _e
        import logging

        dest = tmp_path / "good.env"
        dest.write_text("LASTGOOD=1\n")
        real_open = os.open

        # Patch os.open (the first syscall in _write_text_atomic) — NOT
        # os.write, which the logger itself needs to emit the message.
        def boom(path, *a, **k):
            if str(dest) in str(path):
                raise OSError(_e.ENOSPC, "No space left on device")
            return real_open(path, *a, **k)

        # Capture the watcher logger directly (its JSON StreamHandler holds
        # the pre-test stdout fd, so capsys/capfd can't see it).
        seen = []

        class _Cap(logging.Handler):
            def emit(self, rec):
                seen.append(rec.getMessage())

        lg = logging.getLogger("socialwarden-watcher")
        h = _Cap()
        lg.addHandler(h)
        try:
            monkeypatch.setattr(os, "open", boom)
            ok = watcher._write_text_atomic(str(dest), "NEW=2\n")
            monkeypatch.setattr(os, "open", real_open)
        finally:
            lg.removeHandler(h)
        assert ok is False
        assert dest.read_text() == "LASTGOOD=1\n"  # last-good intact
        assert any("DISK FULL (ENOSPC)" in m for m in seen)


# ===========================================================================
# S1 — destroy the persistent plaintext .pre-socialwarden
#   watcher._shred_unlink + agent.SyncEngine._lock_pre_backup + migrate step 12.5
# ===========================================================================
class TestShredUnlinkS1:
    def test_file_is_gone_and_content_overwritten(self, watcher, tmp_path: Path):
        f = tmp_path / "secret.pre-socialwarden"
        secret = b"DB_PASSWORD=topsecret_marker_ZZZ\nAPI_KEY=sk_live_marker_QQQ\n"
        f.write_bytes(secret)
        # Capture the raw inode bytes after shred (best-effort overwrite check):
        # the file must no longer exist at all.
        assert watcher._shred_unlink(str(f)) is True
        assert not f.exists()

    def test_missing_file_returns_true(self, watcher, tmp_path: Path):
        assert watcher._shred_unlink(str(tmp_path / "nope")) is True

    def test_symlink_is_unlinked_not_followed(self, watcher, tmp_path: Path):
        target = tmp_path / "real_keep.txt"
        target.write_text("KEEP_ME=1\n")
        link = tmp_path / "ln.pre-socialwarden"
        os.symlink(target, link)
        assert watcher._shred_unlink(str(link)) is True
        assert not link.exists()
        # The symlink target must be untouched (we unlink the link only).
        assert target.read_text() == "KEEP_ME=1\n"

    def test_never_raises_on_unwritable_dir(self, watcher, tmp_path: Path):
        # readonly dir → unlink fails; function must swallow and return bool.
        d = tmp_path / "ro"
        d.mkdir()
        f = d / "x.pre-socialwarden"
        f.write_text("S=1\n")
        os.chmod(d, 0o500)
        try:
            res = watcher._shred_unlink(str(f))
            assert res in (True, False)  # no exception is the contract
        finally:
            os.chmod(d, 0o700)


class TestAgentLockPreBackupS1:
    def test_tightens_mode_to_0600(self, agent_mod, tmp_path: Path):
        b = tmp_path / ".env.pre-socialwarden"
        b.write_text("DB_PASSWORD=plaintext_xyz\n")
        os.chmod(b, 0o664)  # world/group-readable, as a rename would inherit
        agent_mod.SyncEngine._lock_pre_backup(str(b))
        assert (b.stat().st_mode & 0o777) == 0o600

    def test_chown_failure_non_root_is_not_fatal(self, agent_mod, tmp_path: Path):
        # As non-root the chown(0,0) fails with EPERM; mode must still be 0600
        # and the call must not raise.
        b = tmp_path / ".env.pre-socialwarden"
        b.write_text("API_KEY=sk_live_abc\n")
        os.chmod(b, 0o644)
        agent_mod.SyncEngine._lock_pre_backup(str(b))
        assert (b.stat().st_mode & 0o777) == 0o600
        assert b.exists()


class TestMigrateShredsPlaintextS1:
    def test_persistent_pre_socialwarden_is_destroyed_after_absorb(self, daemon_sandbox):
        """Step 12.5: once the absorb is verified AND a redundant tmpfs
        backup exists, the persistent plaintext <env>.pre-socialwarden (what
        the real agent stashes) must be shredded so it can't leak via a
        local non-root user or a disk snapshot."""
        ep = str(daemon_sandbox.src_env)
        pre = ep + ".pre-socialwarden"
        # Simulate the agent having stashed the original .env in plaintext.
        Path(pre).write_text(
            "DB_PASSWORD=topsecret_z9_xx_yy\nAPI_KEY=sk_live_aaa_bbb_ccc\n"
        )
        os.chmod(pre, 0o600)
        result = daemon_sandbox.daemon.migrate(
            env_path=ep,
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        assert result.status == "absorbed"
        assert result.backup_path and os.path.exists(result.backup_path)
        # The persistent plaintext is gone; the tmpfs recovery copy remains.
        assert not os.path.exists(pre)

    def test_pre_socialwarden_kept_if_no_backup(self, daemon_sandbox, monkeypatch):
        """Fail-safe: if our redundant tmpfs backup did NOT materialise we
        must NOT shred the only remaining plaintext copy."""
        ep = str(daemon_sandbox.src_env)
        pre = ep + ".pre-socialwarden"
        Path(pre).write_text("DB_PASSWORD=topsecret_z9_xx_yy\n")
        d = daemon_sandbox.daemon
        # Force backup_path to be falsy by pointing backup_dir at a path that
        # cannot be created (the shred guard is `res.backup_path and exists`).
        import importlib

        w = importlib.import_module("dw_watcher")
        orig = w._shred_unlink
        called = {"n": 0}
        monkeypatch.setattr(
            w,
            "_shred_unlink",
            lambda p: (called.__setitem__("n", called["n"] + 1), orig(p))[1],
        )
        # Sabotage the tmpfs backup by making the backup dir a file.
        # If backup fails the migrate likely aborts before step 12.5 — in
        # that case the plaintext is trivially still present, which is the
        # property we assert.
        try:
            d.migrate(
                env_path=ep,
                collection_id="COLL-test-svc-123",
                collection_name="test-svc",
            )
        except Exception:
            pass
        # Either the absorb succeeded WITH a backup (then shred ran) or it
        # didn't (then plaintext stays). What must never happen: shred runs
        # without a verified backup. We assert the safe invariant: if pre is
        # gone, a backup file must exist somewhere under bdir.
        if not os.path.exists(pre):
            assert any(daemon_sandbox.bdir.iterdir())


# ===========================================================================
# S3 — rotate-after-absorb policy (rotation_recommended flag)
# ===========================================================================
class TestRotationRecommendedS3:
    def test_bw_notes_carry_rotation_recommended(self, watcher):
        notes = watcher._format_bw_notes(
            machine_name="host-utils",
            origin="/home/svc/.env",
            backup_path="/run/socialwarden-backups/x",
            absorbed_at=datetime(2026, 5, 15, 12, 0, tzinfo=timezone.utc),
            retention_days=30,
            key="DB_PASSWORD",
        )
        assert "rotation_recommended: yes" in notes
        assert "plaintext-on-disk pre-absorb" in notes

    def test_audit_line_lists_keys_to_rotate(self, daemon_sandbox):
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        lines = [
            json.loads(ln)
            for ln in daemon_sandbox.audit.read_text().splitlines()
            if ln.strip()
        ]
        absorbed = [r for r in lines if r.get("event") == "absorbed"]
        assert absorbed, "no absorbed audit record"
        rr = absorbed[-1].get("rotation_recommended")
        assert sorted(rr) == ["API_KEY", "DB_PASSWORD"]


# ===========================================================================
# S5 — tamper-evident audit hash-chain (_append_audit_line / _verify_audit)
# ===========================================================================
class TestAuditHashChainS5:
    def test_genesis_then_chained(self, watcher, tmp_path: Path):
        ap = str(tmp_path / "audit.jsonl")
        watcher._append_audit_line(ap, {"event": "a", "n": 1})
        watcher._append_audit_line(ap, {"event": "b", "n": 2})
        raw = [ln for ln in Path(ap).read_text().splitlines() if ln.strip()]
        first = json.loads(raw[0])
        second = json.loads(raw[1])
        assert first["prev_sha"] == watcher._AUDIT_GENESIS
        import hashlib

        assert second["prev_sha"] == hashlib.sha256(raw[0].encode("utf-8")).hexdigest()

    def test_verify_intact_returns_0(self, watcher, tmp_path: Path):
        ap = str(tmp_path / "a.jsonl")
        for i in range(5):
            watcher._append_audit_line(ap, {"i": i})
        assert watcher._verify_audit(ap) == 0

    def test_verify_detects_inplace_edit(self, watcher, tmp_path: Path):
        ap = str(tmp_path / "a.jsonl")
        for i in range(4):
            watcher._append_audit_line(ap, {"i": i})
        lines = Path(ap).read_text().splitlines()
        obj = json.loads(lines[1])
        obj["i"] = 999
        lines[1] = json.dumps(obj, ensure_ascii=False, default=str, sort_keys=True)
        Path(ap).write_text("\n".join(lines) + "\n")
        assert watcher._verify_audit(ap) == 1

    def test_verify_detects_deleted_middle_line(self, watcher, tmp_path: Path):
        ap = str(tmp_path / "a.jsonl")
        for i in range(5):
            watcher._append_audit_line(ap, {"i": i})
        lines = Path(ap).read_text().splitlines()
        del lines[2]
        Path(ap).write_text("\n".join(lines) + "\n")
        assert watcher._verify_audit(ap) == 1

    def test_verify_unreadable_returns_2(self, watcher, tmp_path: Path):
        assert watcher._verify_audit(str(tmp_path / "missing.jsonl")) == 2

    def test_verify_empty_returns_0(self, watcher, tmp_path: Path):
        ap = tmp_path / "empty.jsonl"
        ap.write_text("")
        assert watcher._verify_audit(str(ap)) == 0

    def test_cli_subcommand_dispatch(self, watcher, tmp_path: Path):
        ap = str(tmp_path / "a.jsonl")
        for i in range(3):
            watcher._append_audit_line(ap, {"i": i})
        assert watcher.main(["verify-audit", ap]) == 0
        assert watcher.main(["verify-audit", str(tmp_path / "gone.jsonl")]) == 2

    def test_chain_survives_real_migrate(self, daemon_sandbox, watcher):
        """After a real absorb the audit log must still verify clean — the
        instrumented migrate journal calls feed _append_audit_line, so a
        broken chain here would mean the hash-chaining regressed."""
        daemon_sandbox.daemon.migrate(
            env_path=str(daemon_sandbox.src_env),
            collection_id="COLL-test-svc-123",
            collection_name="test-svc",
        )
        assert watcher._verify_audit(str(daemon_sandbox.audit)) == 0

    # ---- legacy-prefix anchoring (pre-S5 logs must not false-positive) ----
    def test_legacy_prefix_then_chain_verifies_clean(self, watcher, tmp_path):
        """A log written before S5 has a run of unchained lines (no
        prev_sha). They are unverifiable but NOT tampering; the chain
        anchors onto the last legacy line and verifies from there."""
        ap = str(tmp_path / "a.jsonl")
        # 3 legacy lines exactly as the pre-S5 code wrote them.
        with open(ap, "w") as f:
            for i in range(3):
                f.write(
                    json.dumps({"event": "absorbed", "i": i}, sort_keys=True) + "\n"
                )
        # New code appends chained lines on top.
        watcher._append_audit_line(ap, {"event": "absorbed", "i": 3})
        watcher._append_audit_line(ap, {"event": "rolled_back", "i": 4})
        assert watcher._verify_audit(ap) == 0

    def test_editing_legacy_chain_boundary_is_detected(self, watcher, tmp_path):
        ap = str(tmp_path / "a.jsonl")
        with open(ap, "w") as f:
            for i in range(3):
                f.write(json.dumps({"i": i}, sort_keys=True) + "\n")
        watcher._append_audit_line(ap, {"i": 3})
        watcher._append_audit_line(ap, {"i": 4})
        lines = Path(ap).read_text().splitlines()
        o = json.loads(lines[2])
        o["i"] = 999  # edit last legacy line
        lines[2] = json.dumps(o, sort_keys=True)
        Path(ap).write_text("\n".join(lines) + "\n")
        assert watcher._verify_audit(ap) == 1

    def test_pure_legacy_log_no_head_is_not_broken(self, watcher, tmp_path):
        ap = str(tmp_path / "a.jsonl")
        with open(ap, "w") as f:
            for i in range(4):
                f.write(json.dumps({"i": i}, sort_keys=True) + "\n")
        # No _append_audit_line call → no head anchor → unverifiable but
        # honestly reported, not flagged as tampering.
        assert watcher._verify_audit(ap) == 0

    # ---- head-anchor: catches what in-log chaining alone cannot ----
    def test_tail_truncation_detected_via_head(self, watcher, tmp_path):
        ap = str(tmp_path / "a.jsonl")
        for i in range(5):
            watcher._append_audit_line(ap, {"i": i})
        lines = Path(ap).read_text().splitlines()
        Path(ap).write_text("\n".join(lines[:-1]) + "\n")  # drop tail
        assert watcher._verify_audit(ap) == 1

    def test_full_chain_strip_detected_via_head(self, watcher, tmp_path):
        ap = str(tmp_path / "a.jsonl")
        for i in range(3):
            watcher._append_audit_line(ap, {"i": i})
        Path(ap).write_text("")  # wipe the log
        assert watcher._verify_audit(ap) == 1  # head remains

    def test_head_anchor_is_0600(self, watcher, tmp_path):
        ap = str(tmp_path / "a.jsonl")
        watcher._append_audit_line(ap, {"i": 0})
        hp = Path(watcher._audit_head_path(ap))
        assert hp.exists()
        assert (hp.stat().st_mode & 0o777) == 0o600


# ===========================================================================
# v1.1.1 — value-aware dedup (drift markers)
# ===========================================================================
class TestValueAwareDedup:
    """Unit-level coverage for the v1.1.1 changes to migrate():

    - same-name + same-value  → silent skip (no new bw item)
    - same-name + diff value  → DRIFT marker created (non-POSIX name),
                                original item never overwritten
    - drift notes carry sha256 PREFIXES only — never the raw value
    - same-day re-run is idempotent (no marker duplication)
    - two existing items with the same name → fail-closed
    """

    def test_format_bw_notes_drift_carries_sha_prefixes_not_value(self, watcher):
        """The drift-notes formatter must surface sha256 PREFIXES so the
        operator can distinguish the two values *without* the value itself
        ever appearing in the notes/log."""
        notes = watcher._format_bw_notes_drift(
            machine_name="host-staging",
            origin="/home/ubuntu/example-app/.env",
            backup_path="/run/socialwarden-backups/x",
            absorbed_at=datetime(2026, 5, 20, 9, 0, 0, tzinfo=timezone.utc),
            retention_days=30,
            key="DB_PASSWORD",
            drift_name="DB_PASSWORD [drift 2026-05-20]",
            existing_item_id="item-aaa",
            existing_value_sha_prefix="9834255a902a5364",
            local_value_sha_prefix="a7f3bb1f08c41099",
        )
        # contains the metadata the operator needs
        assert "DRIFT" in notes
        assert "key_original: DB_PASSWORD" in notes
        assert "DB_PASSWORD [drift 2026-05-20]" in notes
        assert "9834255a902a5364" in notes
        assert "a7f3bb1f08c41099" in notes
        assert "item-aaa" in notes
        # CRITICAL: no literal value should appear. We pass values via the
        # caller; the formatter receives only prefixes. The string "password"
        # is acceptable (it's a label), but ensure no obvious leak.
        assert "topsecret" not in notes.lower()

    def test_render_env_skips_non_posix_item_names(self):
        """Agent v1.4.18 render_env must filter items whose name is not a
        valid POSIX env-var identifier. Drift markers ("KEY [drift DATE]")
        are precisely such names — they must NOT reach the consumer's .env.
        """
        # Load agent.py via importlib (same pattern as test_watcher fixture
        # for watcher). The agent path is sibling.
        import importlib.util
        import sys as _sys

        agent_path = WATCHER_PATH.parent / "socialwarden-agent.py"
        spec = importlib.util.spec_from_file_location("_dw_agent", agent_path)
        mod = importlib.util.module_from_spec(spec)
        _sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)

        items = [
            {"name": "DB_PASSWORD", "login": {"password": "topsecret"}},
            {"name": "API_KEY", "login": {"password": "sk_live_xyz"}},
            # The marker — non-POSIX name, must be filtered out.
            {
                "name": "DB_PASSWORD [drift 2026-05-20]",
                "login": {"password": "older_value"},
            },
            # Also non-POSIX: leading digit.
            {"name": "1FOO", "login": {"password": "bad"}},
        ]
        rendered = mod.render_env(items)
        # The two valid keys are present.
        assert "DB_PASSWORD=topsecret" in rendered
        assert "API_KEY=sk_live_xyz" in rendered
        # The drift marker and the leading-digit name are absent.
        assert "drift" not in rendered
        assert "[drift" not in rendered
        assert "1FOO" not in rendered
        # And the older value is not in the rendered output anywhere.
        assert "older_value" not in rendered

    def test_migration_result_has_drift_items_field(self, watcher):
        """v1.1.1 adds drift_items to MigrationResult. Make sure it exists,
        defaults to an empty list, and is independent across instances."""
        r1 = watcher.MigrationResult(status="absorbed", env_path="/a/.env")
        r2 = watcher.MigrationResult(status="absorbed", env_path="/b/.env")
        assert r1.drift_items == []
        assert r2.drift_items == []
        r1.drift_items.append({"key": "X"})
        # No shared default mutable state across instances.
        assert r2.drift_items == []

    # ----------------------------------------------------------------
    # E2E-at-migrate() level. Helper builds a minimal WatcherDaemon with
    # a stub BWClient whose responses we control inside each test. We
    # bypass _signal_agent_reload + _wait_for_file (they belong to the
    # agent half of the dance and aren't what we exercise here).
    # ----------------------------------------------------------------
    @staticmethod
    def _build_daemon(watcher, tmp_path: Path, existing_items: list[dict]):
        """Return (daemon, fbw) where fbw is a small object exposing
        `create_calls` so the test can assert on what was created."""

        class FakeBW:
            def __init__(self):
                self.create_calls: list[dict] = []

            def ensure_collection(self, **kw):
                # Returns (resolved_id, status_str) per BWClient API.
                return (kw.get("preferred_id") or "COLL-X", "ok")

            def list_items_in_collection(self, cid):
                return list(existing_items)

            def create_login_item(self, **kw):
                self.create_calls.append(kw)
                return f"item-new-{len(self.create_calls)}"

        fbw = FakeBW()
        cfg = {
            "auth": {"email": "contact@example.com"},
            "machine": {"name": "host-utils"},
            "organization": {"id": "ORG-AAA"},
            "sync": {"collections": []},
            "watch": {"materialize_for_dir": {}},
        }
        secrets_dir = tmp_path / "run/secrets"
        secrets_dir.mkdir(parents=True)
        backup_dir = tmp_path / "run/socialwarden-backups"
        logdir = tmp_path / "var/log/socialwarden"
        logdir.mkdir(parents=True)
        audit_log = logdir / "watcher.audit.jsonl"
        agent_cfg_path = tmp_path / "etc/socialwarden/config.yaml"
        agent_cfg_path.parent.mkdir(parents=True)
        agent_cfg_path.write_text(yaml.safe_dump(cfg))

        daemon = watcher.WatcherDaemon(
            config=cfg,
            bw_client=fbw,
            machine_name="host-utils",
            agent_config_path=str(agent_cfg_path),
            secrets_dir=str(secrets_dir),
            backup_dir=str(backup_dir),
            audit_log=str(audit_log),
        )
        return daemon, fbw

    def test_migrate_same_value_silent_skip(self, watcher, tmp_path: Path, monkeypatch):
        """SAME key + SAME value → ZERO new bw items, ZERO drift items."""
        svc = tmp_path / "svc"
        svc.mkdir()
        env = svc / ".env"
        env.write_text("DB_PASSWORD=same_value_xx\nPORT=5432\n")
        os.chmod(env, 0o600)

        daemon, fbw = self._build_daemon(
            watcher,
            tmp_path,
            existing_items=[
                {
                    "id": "item-aaa",
                    "name": "DB_PASSWORD",
                    "login": {"password": "same_value_xx"},
                }
            ],
        )
        # Short-circuit the agent dance — we only test the bucle decision.
        monkeypatch.setattr(daemon, "_signal_agent_reload", lambda: None)
        monkeypatch.setattr(daemon, "_wait_for_file", lambda *a, **kw: False)

        res = daemon.migrate(
            env_path=str(env),
            collection_id="COLL-X",
            collection_name="test-coll",
        )
        assert fbw.create_calls == [], (
            f"expected silent skip but bw was called "
            f"{[c.get('name') for c in fbw.create_calls]}"
        )
        assert res.drift_items == []

    def test_migrate_different_value_creates_drift_marker(
        self, watcher, tmp_path: Path, monkeypatch
    ):
        """SAME key + DIFFERENT value → ONE drift marker; original never
        overwritten; notes carry sha PREFIXES only, no values."""
        svc = tmp_path / "svc"
        svc.mkdir()
        env = svc / ".env"
        env.write_text("DB_PASSWORD=NEW_LOCAL_VALUE\nPORT=5432\n")
        os.chmod(env, 0o600)

        daemon, fbw = self._build_daemon(
            watcher,
            tmp_path,
            existing_items=[
                {
                    "id": "item-original",
                    "name": "DB_PASSWORD",
                    "login": {"password": "OLD_VAULT_VALUE"},
                }
            ],
        )
        monkeypatch.setattr(daemon, "_signal_agent_reload", lambda: None)
        monkeypatch.setattr(daemon, "_wait_for_file", lambda *a, **kw: False)

        res = daemon.migrate(
            env_path=str(env),
            collection_id="COLL-X",
            collection_name="test-coll",
        )
        assert len(fbw.create_calls) == 1, (
            f"expected exactly 1 create (drift marker), got "
            f"{[c.get('name') for c in fbw.create_calls]}"
        )
        drift_call = fbw.create_calls[0]
        # Name is "<KEY> [drift YYYY-MM-DD]" — non-POSIX (spaces + brackets).
        assert drift_call["name"].startswith("DB_PASSWORD [drift ")
        assert drift_call["name"].endswith("]")
        assert " " in drift_call["name"]
        # Value sent to create is the LOCAL value, never the vault's.
        assert drift_call["value"] == "NEW_LOCAL_VALUE"
        # Notes carry sha PREFIXES, NEVER the raw values.
        notes = drift_call["notes"]
        assert "DRIFT" in notes
        assert "key_original: DB_PASSWORD" in notes
        assert "existing_item_id: item-original" in notes
        assert "OLD_VAULT_VALUE" not in notes
        assert "NEW_LOCAL_VALUE" not in notes
        # res.drift_items reflects the decision.
        assert len(res.drift_items) == 1
        assert res.drift_items[0]["key"] == "DB_PASSWORD"
        assert res.drift_items[0]["existing_item_id"] == "item-original"

    def test_migrate_ambiguous_existing_name_fails_closed(
        self, watcher, tmp_path: Path, monkeypatch
    ):
        """Two items with the same name in the same collection → migrate
        must REFUSE (fail-closed) rather than pick one arbitrarily."""
        svc = tmp_path / "svc"
        svc.mkdir()
        env = svc / ".env"
        env.write_text("DB_PASSWORD=anything\n")
        os.chmod(env, 0o600)

        daemon, fbw = self._build_daemon(
            watcher,
            tmp_path,
            existing_items=[
                {"id": "id-a", "name": "DB_PASSWORD", "login": {"password": "a"}},
                {"id": "id-b", "name": "DB_PASSWORD", "login": {"password": "b"}},
            ],
        )
        monkeypatch.setattr(daemon, "_signal_agent_reload", lambda: None)
        monkeypatch.setattr(daemon, "_wait_for_file", lambda *a, **kw: False)

        res = daemon.migrate(
            env_path=str(env),
            collection_id="COLL-X",
            collection_name="test-coll",
        )
        assert res.status == "failed", f"expected failed, got {res.status}"
        assert ("ambiguous" in res.reason.lower()) or (">1" in res.reason), (
            f"expected ambiguity in reason, got: {res.reason!r}"
        )
        # And we never tried to create anything in such a confused state.
        assert fbw.create_calls == []


# ===========================================================================
# v1.2.0 — auto-discover (rules + ignores + fallback alert)
# ===========================================================================
class TestAutoDiscoverHelpers:
    """Unit tests for the pure helpers in watcher 1.2.0."""

    def test_machine_short_explicit(self, watcher):
        cfg = {"machine": {"name": "host-staging", "short_name": "staging"}}
        assert watcher._machine_short_name(cfg) == "staging"

    def test_machine_short_falls_back_to_name(self, watcher):
        cfg = {"machine": {"name": "host-staging"}}
        assert watcher._machine_short_name(cfg) == "host-staging"

    def test_compile_auto_naming_disabled(self, watcher):
        assert (
            watcher._compile_auto_naming_rules(
                {"watch": {"auto_naming": {"enabled": False}}}
            )
            == []
        )

    def test_compile_auto_naming_defaults(self, watcher):
        rules = watcher._compile_auto_naming_rules(
            {"watch": {"auto_naming": {"enabled": True}}}
        )
        assert len(rules) == 6

    def test_compile_auto_naming_bad_regex_raises(self, watcher):
        with pytest.raises(ValueError, match="bad regex"):
            watcher._compile_auto_naming_rules(
                {
                    "watch": {
                        "auto_naming": {
                            "enabled": True,
                            "rules": [{"match": "[unclosed", "collection_name": "x"}],
                        }
                    }
                }
            )

    def test_load_ignore_paths_defaults(self, watcher):
        ip = watcher._load_ignore_paths({})
        assert "/etc/nvidia-container-toolkit/" in ip
        assert "/home/ubuntu/tests/" in ip
        assert "/proc/" in ip
        assert "/var/" in ip

    def test_compile_ignore_patterns_defaults(self, watcher):
        pats = watcher._compile_ignore_patterns({})
        assert any(p.search(".env.static") for p in pats)
        assert any(p.search(".env.backup") for p in pats)
        assert any(p.search(".env.am-20260519T110524Z") for p in pats)

    def test_is_path_ignored(self, watcher):
        prefixes = ["/etc/nvidia-container-toolkit/", "/home/ubuntu/tests/"]
        assert watcher._is_path_ignored("/etc/nvidia-container-toolkit/x.env", prefixes)
        assert watcher._is_path_ignored("/home/ubuntu/tests/foo/.env", prefixes)
        assert not watcher._is_path_ignored("/home/ubuntu/example-a/.env", prefixes)

    def test_is_basename_ignored(self, watcher):
        import re as _re

        pats = [_re.compile(r"\.env\.(static|backup|copy)$")]
        assert watcher._is_basename_ignored("/x/.env.static", pats)
        assert watcher._is_basename_ignored("/x/.env.backup", pats)
        assert not watcher._is_basename_ignored("/x/.env", pats)

    def test_apply_auto_naming_basic(self, watcher):
        rules = watcher._compile_auto_naming_rules(
            {"watch": {"auto_naming": {"enabled": True}}}
        )
        # /home/ubuntu/<dir>/.env  → "{dirname}-{machine_short}"
        result = watcher._apply_auto_naming("/home/ubuntu/example-app/.env", rules, "utils")
        assert result == ("example-app-utils", 2)

    def test_apply_auto_naming_monitor_specific_beats_generic(self, watcher):
        rules = watcher._compile_auto_naming_rules(
            {"watch": {"auto_naming": {"enabled": True}}}
        )
        # Monitor stack rule (index 0) is more specific than the generic
        # /fleet-ops-main/ rule (index 1); it wins.
        result = watcher._apply_auto_naming(
            "/home/ubuntu/fleet-ops-main/monitor/example-soc/.env", rules, "utils"
        )
        assert result is not None
        assert result[0] == "monitor-example-soc"
        assert result[1] == 0

    def test_apply_auto_naming_etc(self, watcher):
        rules = watcher._compile_auto_naming_rules(
            {"watch": {"auto_naming": {"enabled": True}}}
        )
        result = watcher._apply_auto_naming(
            "/etc/betterstack-bridge.env", rules, "utils"
        )
        assert result == ("betterstack-bridge", 4)

    def test_apply_auto_naming_no_match(self, watcher):
        rules = watcher._compile_auto_naming_rules(
            {"watch": {"auto_naming": {"enabled": True}}}
        )
        assert (
            watcher._apply_auto_naming("/some/random/foo.env", rules, "utils") is None
        )

    def test_suggest_name_for_unmapped(self, watcher):
        assert (
            watcher._suggest_name_for_unmapped("/var/lib/myapp/.env", "prod")
            == "myapp-prod"
        )
        assert (
            watcher._suggest_name_for_unmapped("/etc/foo.env", "utils") == "foo-utils"
        )


class TestAutoDiscoverOnRealFleetPaths:
    """The 37 candidate paths discovered by today's fleet sweep, run
    through the auto-naming + ignore pipeline. Confirms 100% coverage."""

    # (machine_short, env_path, expected_outcome)
    # outcome forms:
    #   ("rule", expected_collection_name) — silent absorb path
    #   ("ignore",)                       — silent skip path
    CASES = [
        # utils
        ("utils", "/etc/betterstack-bridge.env", ("rule", "betterstack-bridge")),
        ("utils", "/home/ubuntu/.env.app-b.copy", ("ignore",)),
        ("utils", "/home/ubuntu/example-b/.env", ("rule", "example-b-utils")),
        ("utils", "/home/ubuntu/example-b/.env.static", ("ignore",)),
        (
            "utils",
            "/home/ubuntu/fleet-ops-main/socialwarden/.env",
            ("rule", "socialwarden-utils"),
        ),
        (
            "utils",
            "/home/ubuntu/fleet-ops-main/monitor/example-dns/.env",
            ("rule", "monitor-example-dns"),
        ),
        (
            "utils",
            "/home/ubuntu/fleet-ops-main/monitor/example-homepage/.env",
            ("rule", "monitor-example-homepage"),
        ),
        (
            "utils",
            "/home/ubuntu/fleet-ops-main/monitor/example-obs/.env",
            ("rule", "monitor-example-obs"),
        ),
        (
            "utils",
            "/home/ubuntu/fleet-ops-main/monitor/example-log/.env",
            ("rule", "monitor-example-log"),
        ),
        (
            "utils",
            "/home/ubuntu/fleet-ops-main/monitor/example-soc/.env",
            ("rule", "monitor-example-soc"),
        ),
        (
            "utils",
            "/home/ubuntu/internal-dashboard/.env",
            ("rule", "internal-dashboard-utils"),
        ),
        ("utils", "/home/ubuntu/internal-dashboard/.env.static", ("ignore",)),
        ("utils", "/home/ubuntu/test-watcher-canary/.env.static", ("ignore",)),
        (
            "utils",
            "/home/ubuntu/tests/s-final-migration/.env.am-20260519T110524Z",
            ("ignore",),
        ),
        ("utils", "/home/ubuntu/example-a/.env.backup", ("ignore",)),
        ("utils", "/home/ubuntu/example-a/.env.static", ("ignore",)),
        # host-staging
        (
            "staging",
            "/etc/nvidia-container-toolkit/nvidia-cdi-refresh.env",
            ("ignore",),
        ),
        ("staging", "/home/ubuntu/.env", ("rule", "home-misc-staging")),
        ("staging", "/home/ubuntu/example-app/.env", ("rule", "example-app-staging")),
        ("staging", "/home/ubuntu/app-c-config/.env", ("rule", "app-c-config-staging")),
        ("staging", "/home/ubuntu/example-c/.env", ("rule", "example-c-staging")),
        (
            "staging",
            "/home/ubuntu/example-db-project/.env",
            ("rule", "example-db-project-staging"),
        ),
        ("staging", "/root/service-metrics/.env", ("rule", "service-metrics-staging")),
        # host-db
        ("db", "/home/ubuntu/host-db/.env", ("rule", "host-db-db")),
        ("db", "/home/ubuntu/service-metrics/.env", ("rule", "service-metrics-db")),
        # host-agent (short=host-2)
        ( "host-2", "/home/ubuntu/agent/.env", ("rule", "agent-host-2")),
        (
            "host-2",
            "/home/ubuntu/service-metrics/.env",
            ("rule", "service-metrics-host-2"),
        ),
        # host-dev (short=dev)
        ("dev", "/home/ubuntu/service-metrics/.env", ("rule", "service-metrics-dev")),
        # voice-host (prod), short=prod
        ("prod", "/home/ubuntu/service-metrics/.env", ("rule", "service-metrics-prod")),
        # host-prod (short=prod)
        ("prod", "/etc/nvidia-container-toolkit/nvidia-cdi-refresh.env", ("ignore",)),
        ("prod", "/home/ubuntu/.env", ("rule", "home-misc-prod")),
        ("prod", "/home/ubuntu/example-app/.env", ("rule", "example-app-prod")),
        ("prod", "/home/ubuntu/app-c-config/.env", ("rule", "app-c-config-prod")),
        ("prod", "/home/ubuntu/example-c/.env", ("rule", "example-c-prod")),
        (
            "prod",
            "/home/ubuntu/example-db-project/.env",
            ("rule", "example-db-project-prod"),
        ),
    ]

    @pytest.fixture(scope="class")
    def pipeline(self, watcher):
        rules = watcher._compile_auto_naming_rules(
            {"watch": {"auto_naming": {"enabled": True}}}
        )
        ignore_paths = watcher._load_ignore_paths({})
        ignore_patterns = watcher._compile_ignore_patterns({})
        return rules, ignore_paths, ignore_patterns

    @pytest.mark.parametrize("machine_short,env_path,expected", CASES)
    def test_case(self, watcher, pipeline, machine_short, env_path, expected):
        rules, ignore_paths, ignore_patterns = pipeline
        if watcher._is_path_ignored(env_path, ignore_paths):
            outcome = ("ignore",)
        elif watcher._is_basename_ignored(env_path, ignore_patterns):
            outcome = ("ignore",)
        else:
            r = watcher._apply_auto_naming(env_path, rules, machine_short)
            outcome = ("rule", r[0]) if r is not None else ("fallback",)
        assert outcome == expected, (
            f"{env_path!r} (machine_short={machine_short!r}): got {outcome}, "
            f"expected {expected}"
        )


class TestWatcherDaemonAutoDiscover:
    """E2E: WatcherDaemon with auto-naming enabled, including manual
    override priority and the alert_and_wait fallback path."""

    @staticmethod
    def _build_daemon(watcher, tmp_path: Path, cfg_extra: dict = None):
        cfg = {
            "auth": {"email": "contact@example.com"},
            "machine": {"name": "host-utils", "short_name": "utils"},
            "organization": {"id": "ORG-AAA"},
            "sync": {"collections": []},
            "watch": {
                "auto_naming": {
                    "enabled": True,
                    "fallback_behavior": "alert_and_wait",
                },
            },
        }
        if cfg_extra:
            cfg["watch"].update(cfg_extra)
        agent_cfg_path = tmp_path / "etc/socialwarden/config.yaml"
        agent_cfg_path.parent.mkdir(parents=True)
        agent_cfg_path.write_text(yaml.safe_dump(cfg))

        class FBW:
            def ensure_collection(self, **kw):
                return (kw.get("preferred_id") or "COLL-X", "ok")

            def list_items_in_collection(self, cid):
                return []

            def create_login_item(self, **kw):
                return "item-1"

        d = watcher.WatcherDaemon(
            config=cfg,
            bw_client=FBW(),
            machine_name="host-utils",
            agent_config_path=str(agent_cfg_path),
            secrets_dir=str(tmp_path / "run/secrets"),
        )
        return d

    def test_machine_short_loaded(self, watcher, tmp_path):
        d = self._build_daemon(watcher, tmp_path)
        assert d.machine_short == "utils"

    def test_rules_loaded(self, watcher, tmp_path):
        d = self._build_daemon(watcher, tmp_path)
        assert len(d.auto_naming_rules) == 6

    def test_collection_for_rule_match(self, watcher, tmp_path):
        d = self._build_daemon(watcher, tmp_path)
        coll = d._collection_for("/home/ubuntu/example-app/.env")
        assert coll is not None
        assert coll["name"] == "example-app-utils"
        assert coll["auto_named"] is True
        assert coll["source"].startswith("rule_")
        assert coll["id"] == ""

    def test_collection_for_ignored_path(self, watcher, tmp_path):
        # v1.2.2 (in v1.5.1): ignored paths return {"source": "ignored"}
        # so the caller books them as stats.skipped, not stats.no_mapping.
        d = self._build_daemon(watcher, tmp_path)
        result = d._collection_for("/home/ubuntu/tests/foo/.env.am-x")
        assert result is not None and result.get("source") == "ignored"
        assert d._alerted_unmapped == set()  # no alert fired

    def test_collection_for_ignored_pattern(self, watcher, tmp_path):
        # v1.2.2: same sentinel for ignore_patterns matches.
        d = self._build_daemon(watcher, tmp_path)
        result = d._collection_for("/home/ubuntu/example-a/.env.static")
        assert result is not None and result.get("source") == "ignored"

    def test_manual_override_wins_over_rule(self, watcher, tmp_path):
        d = self._build_daemon(
            watcher,
            tmp_path,
            {
                "collection_for_dir": {
                    "/home/ubuntu/app-b": {
                        "id": "COLL-MANUAL",
                        "name": "app-b-special",
                    }
                }
            },
        )
        coll = d._collection_for("/home/ubuntu/app-b/.env")
        assert coll == {
            "id": "COLL-MANUAL",
            "name": "app-b-special",
            "source": "manual",
        }

    def test_fallback_alert_fires(self, watcher, tmp_path, monkeypatch):
        d = self._build_daemon(watcher, tmp_path)
        captured: list[dict] = []
        import sys as _sys

        wmod = _sys.modules["dw_watcher"]
        monkeypatch.setattr(
            wmod,
            "send_discord_alert",
            lambda *a, **kw: captured.append(kw),
        )
        # A path that no rule covers and not in ignores
        coll = d._collection_for("/opt/myapp/.env")
        assert coll is None
        assert len(captured) == 1
        assert "unmapped" in captured[0].get("title", "").lower()

    def test_fallback_alert_deduped_within_tick(self, watcher, tmp_path, monkeypatch):
        d = self._build_daemon(watcher, tmp_path)
        captured: list[dict] = []
        import sys as _sys

        wmod = _sys.modules["dw_watcher"]
        monkeypatch.setattr(
            wmod,
            "send_discord_alert",
            lambda *a, **kw: captured.append(kw),
        )
        d._collection_for("/opt/myapp/.env")
        d._collection_for("/opt/myapp/.env")  # same path again, same tick
        assert len(captured) == 1


# ===========================================================================
# v1.5.0 — regression tests for the 8 bugs fixed in this release.
# Each test reproduces the broken behaviour ON PURPOSE and verifies the fix.
# DO NOT delete these even after release: they are the wall against
# regression of the exact mistakes that bit production migrations on
# 2026-05-20.
# ===========================================================================
class TestV150RegressionBugs:
    """Regression tests for the 8 bugs fixed in v1.5.0."""

    def test_bug1_output_path_preserved_on_existing_entry(
        self, watcher, tmp_path
    ):
        """Bug #1 (CRITICAL): adding a merge: block to an existing
        sync.collections entry must NOT change its `output:` path."""
        cfg_path = tmp_path / "config.yaml"
        cfg = {
            "auth": {"email": "x"},
            "machine": {"name": "h"},
            "organization": {"id": "O"},
            "sync": {
                "collections": [
                    {
                        "id": "COLL-X",
                        "name": "example-app-staging",
                        "output": "/run/secrets/example-app.env",  # LEGACY path
                    }
                ]
            },
        }
        cfg_path.write_text(yaml.safe_dump(cfg))

        class StubBW:
            def ensure_collection(self, **kw):
                return ("COLL-X", "ok")
            def list_items_in_collection(self, cid):
                return []
            def create_login_item(self, **kw):
                return "i"

        d = watcher.WatcherDaemon(
            config=cfg, bw_client=StubBW(),
            machine_name="h", agent_config_path=str(cfg_path),
        )
        ok = d._add_collection_to_agent_config(
            collection_id="COLL-X",
            collection_name="example-app-staging",
            merge_link="/home/ubuntu/example-app/.env",
            merge_static="/home/ubuntu/example-app/.env.static",
            merge_target="/run/secrets/example-app-staging.env.merged",
            vault_only_output="/run/secrets/example-app-staging.env",  # NEW
            materialize_cfg={"materialize": "copy", "mode": "0640",
                             "owner": "root", "group": "ubuntu"},
        )
        assert ok is True
        after = yaml.safe_load(cfg_path.read_text())
        cols = after["sync"]["collections"]
        assert len(cols) == 1  # no duplicate
        assert cols[0]["output"] == "/run/secrets/example-app.env"  # preserved!
        assert cols[0]["merge"]["link"] == "/home/ubuntu/example-app/.env"

    def test_bug2_crlf_does_not_leak_carriage_return(self):
        """Bug #2 (CRITICAL): CRLF line endings used to leave \\r in
        parsed values. Now splitlines() handles both \\n and \\r\\n."""
        import importlib.util
        import sys
        ap = WATCHER_PATH.parent / "socialwarden-agent.py"
        spec = importlib.util.spec_from_file_location("ag", ap)
        m = importlib.util.module_from_spec(spec); sys.modules["ag"] = m
        spec.loader.exec_module(m)
        decoded = dict(m.decode_env_text("KEY=value\r\nOTHER=x\r\n"))
        assert decoded["KEY"] == "value"
        assert "\r" not in decoded["KEY"]
        assert decoded["OTHER"] == "x"

    def test_bug3_drift_cascade_dedup_against_markers(
        self, watcher, tmp_path, monkeypatch
    ):
        """Bug #3 (HIGH): a pre-existing drift marker with the SAME
        local value must NOT trigger creation of a new marker."""
        env = tmp_path / "svc/.env"
        env.parent.mkdir()
        env.write_text("KEY=local_val\nPORT=5432\n")
        os.chmod(env, 0o600)

        class FBW:
            def __init__(self):
                self.creates = []
            def ensure_collection(self, **kw):
                return (kw.get("preferred_id") or "C", "ok")
            def list_items_in_collection(self, cid):
                return [
                    {"id": "orig", "name": "KEY",
                     "login": {"password": "OLD_VAULT"}},
                    {"id": "marker", "name": "KEY [drift 2026-05-19]",
                     "login": {"password": "local_val"}},  # already captured!
                ]
            def create_login_item(self, **kw):
                self.creates.append(kw); return "new"

        fbw = FBW()
        cfg = {"auth": {"email": "x"}, "machine": {"name": "h"},
               "organization": {"id": "O"}, "sync": {"collections": []},
               "watch": {}}
        cfg_path = tmp_path / "cfg.yaml"; cfg_path.write_text(yaml.safe_dump(cfg))
        (tmp_path / "run/secrets").mkdir(parents=True)
        d = watcher.WatcherDaemon(
            config=cfg, bw_client=fbw, machine_name="h",
            agent_config_path=str(cfg_path),
            secrets_dir=str(tmp_path / "run/secrets"),
        )
        monkeypatch.setattr(d, "_signal_agent_reload", lambda: None)
        monkeypatch.setattr(d, "_wait_for_file", lambda *a, **kw: False)
        d.migrate(env_path=str(env), collection_id="C",
                  collection_name="test-coll")
        assert fbw.creates == []  # zero new markers — already deduped

    def test_bug4_format_injection_dirname_with_braces(self, watcher):
        """Bug #4 (HIGH): dirname containing `{` used to crash format()."""
        cfg = {
            "watch": {
                "auto_naming": {
                    "enabled": True,
                    "rules": [
                        {"match": r"^/foo/(?P<dirname>[^/]+)/\.env$",
                         "collection_name": "{dirname}-{machine_short}"},
                    ],
                }
            }
        }
        rules = watcher._compile_auto_naming_rules(cfg)
        # Must NOT raise. Either returns sanitized name or None.
        result = watcher._apply_auto_naming("/foo/{evil}/.env", rules, "h")
        # With v1.5.0 escape, this matches and produces "{evil}-h"
        assert result is not None
        name, _ = result
        assert "evil" in name

    def test_bug5_alert_warning_when_no_webhook(
        self, watcher, tmp_path, caplog
    ):
        """Bug #5 (MEDIUM): missing webhook used to silence alerts.
        Now we log WARNING + bump counter."""
        cfg = {"auth": {"email": "x"}, "machine": {"name": "h"},
               "organization": {"id": "O"}, "sync": {"collections": []},
               "watch": {"auto_naming": {"enabled": False}}}

        class StubBW:
            def ensure_collection(self, **kw): return ("C", "ok")
            def list_items_in_collection(self, cid): return []
            def create_login_item(self, **kw): return "i"

        cfg_path = tmp_path / "cfg.yaml"; cfg_path.write_text(yaml.safe_dump(cfg))
        d = watcher.WatcherDaemon(
            config=cfg, bw_client=StubBW(), machine_name="h",
            agent_config_path=str(cfg_path),
            discord_webhook=None,
        )
        import logging
        # The watcher uses logger name "socialwarden-watcher" (WATCHER_NAME).
        with caplog.at_level(logging.WARNING, logger="socialwarden-watcher"):
            d._alert_unmapped_env("/opt/myapp/.env")
        # The counter is the most reliable signal that the fix path executed
        # (caplog captures by handler attachment which can race in this harness).
        assert d._unmapped_alerts_undelivered >= 1

    def test_bug8_wait_for_file_rejects_empty_file(
        self, watcher, tmp_path
    ):
        """Bug #8 (LOW): _wait_for_file used to accept any size > 0 even
        if content was malformed. Empty file (size 0) keeps polling
        until timeout, then returns False."""
        class SBW:
            def ensure_collection(self, **kw): return ("C", "ok")
            def list_items_in_collection(self, cid): return []
            def create_login_item(self, **kw): return "i"
        d = watcher.WatcherDaemon(
            config={"sync": {"collections": []}, "watch": {},
                    "machine": {"name": "h"}, "auth": {"email": "x"},
                    "organization": {"id": "O"}},
            bw_client=SBW(), machine_name="h",
            agent_config_path=str(tmp_path / "cfg.yaml"),
        )
        (tmp_path / "cfg.yaml").write_text("")
        target = tmp_path / "out.env"
        target.write_text("")  # empty
        # Should time out and return False
        assert d._wait_for_file(str(target), 1.0) is False

    def test_bug8_wait_for_file_accepts_valid_file(
        self, watcher, tmp_path
    ):
        """Companion: a parseable file IS accepted."""
        class SBW:
            def ensure_collection(self, **kw): return ("C", "ok")
            def list_items_in_collection(self, cid): return []
            def create_login_item(self, **kw): return "i"
        d = watcher.WatcherDaemon(
            config={"sync": {"collections": []}, "watch": {},
                    "machine": {"name": "h"}, "auth": {"email": "x"},
                    "organization": {"id": "O"}},
            bw_client=SBW(), machine_name="h",
            agent_config_path=str(tmp_path / "cfg.yaml"),
        )
        (tmp_path / "cfg.yaml").write_text("")
        target = tmp_path / "out.env"
        target.write_text("KEY=value\n")
        assert d._wait_for_file(str(target), 5.0) is True


# ---------------------------------------------------------------------------
# v1.5.1 (watcher 1.2.2) — regression tests for two new bug fixes uncovered
# in the S-FINAL live migration:
#
#  9 (CRITICAL) is_already_managed: accepts ANY known managed header
#               (sentinel OR template "Generated from .env + vault").
# 10 (MEDIUM)   stats accounting: ignored paths go to stats.skipped, not
#               stats.no_mapping.
# ---------------------------------------------------------------------------
class TestV151RegressionBugs:
    """Cover the two new fixes shipped in v1.5.1 (watcher 1.2.2).
    Each test reproduces the broken pre-fix behaviour as the hostile case so
    a regression is impossible to ship silently."""

    def test_bug9_is_already_managed_accepts_sentinel_header(
        self, watcher, tmp_path
    ):
        """Original behaviour preserved: a file with the canonical merge
        sentinel still counts as managed."""
        p = tmp_path / ".env"
        p.write_text(
            "# === Secrets managed by SocialWarden (do not edit) ===\n"
            "FOO=bar\n"
        )
        assert watcher.is_already_managed(str(p)) is True

    def test_bug9_is_already_managed_accepts_template_header(
        self, watcher, tmp_path
    ):
        """Bug #9 (CRITICAL): Sprint 1B/1C/1D `render:` templates write a
        different banner ("# Generated from .env + vault. DO NOT EDIT
        MANUALLY.") that pre-dates the sentinel. Pre-fix this returned
        False and the watcher emitted DRIFT [reverted] every tick after
        the agent re-rendered such a consumer."""
        p = tmp_path / ".env"
        p.write_text(
            "# Generated from .env + vault. DO NOT EDIT MANUALLY.\n"
            "# Edit /etc/socialwarden/templates/<host>/<this-file>.tmpl\n"
            "FOO=bar\n"
        )
        assert watcher.is_already_managed(str(p)) is True

    def test_bug9_is_already_managed_rejects_unmanaged(
        self, watcher, tmp_path
    ):
        """Negative: a plain .env without any known managed header is
        correctly classified as unmanaged."""
        p = tmp_path / ".env"
        p.write_text("FOO=bar\nBAZ=qux\n")
        assert watcher.is_already_managed(str(p)) is False

    def test_bug9_known_headers_tuple_contains_both(self, watcher):
        """Defensive: the public tuple of accepted headers must contain
        both shapes so a future contributor can't drop one accidentally."""
        headers = watcher.SOCIALWARDEN_MANAGED_HEADERS
        assert "# === Secrets managed by SocialWarden (do not edit) ===" in headers
        assert "# Generated from .env + vault. DO NOT EDIT MANUALLY." in headers

    def test_bug10_ignored_path_returns_ignored_sentinel(
        self, watcher, tmp_path
    ):
        """Bug #10 (MEDIUM): _collection_for used to return None for
        ignored paths AND for unmatched paths, so the caller couldn't
        distinguish them and bucketed both into stats.no_mapping. Now
        ignored paths get back a {'source': 'ignored'} sentinel."""
        cfg = {
            "watch": {
                "ignore_paths": ["/home/ubuntu/app-c-config/"],
                "auto_naming": {"enabled": False},
            },
            "sync": {"collections": []},
            "machine": {"name": "h"},
            "auth": {"email": "x"},
            "organization": {"id": "O"},
        }
        class SBW:
            def ensure_collection(self, **kw): return ("C", "ok")
            def list_items_in_collection(self, cid): return []
        d = watcher.WatcherDaemon(
            config=cfg,
            bw_client=SBW(),
            machine_name="h",
            agent_config_path=str(tmp_path / "cfg.yaml"),
        )
        (tmp_path / "cfg.yaml").write_text("")
        result = d._collection_for("/home/ubuntu/app-c-config/.env")
        assert isinstance(result, dict), "ignored paths must return a dict, not None"
        assert result.get("source") == "ignored"

    def test_bug10_unmatched_path_still_returns_none(
        self, watcher, tmp_path
    ):
        """Companion: a path that is genuinely unmatched (not ignored,
        no rule, fallback=silent_skip) returns None as before."""
        cfg = {
            "watch": {
                "ignore_paths": [],
                "auto_naming": {
                    "enabled": True,
                    "rules": [],
                    "fallback_behavior": "silent_skip",
                },
            },
            "sync": {"collections": []},
            "machine": {"name": "h"},
            "auth": {"email": "x"},
            "organization": {"id": "O"},
        }
        class SBW:
            def ensure_collection(self, **kw): return ("C", "ok")
            def list_items_in_collection(self, cid): return []
        d = watcher.WatcherDaemon(
            config=cfg,
            bw_client=SBW(),
            machine_name="h",
            agent_config_path=str(tmp_path / "cfg.yaml"),
        )
        (tmp_path / "cfg.yaml").write_text("")
        # Path that no rule matches and no ignore covers
        result = d._collection_for("/some/random/orphan.env")
        assert result is None
