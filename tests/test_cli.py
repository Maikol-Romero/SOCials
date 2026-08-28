"""Tests for socials.cli — argument parsing and subcommands."""

from socials.cli import build_parser
from socials import __version__


class TestParser:
    def setup_method(self):
        self.parser = build_parser()

    def test_status_subcommand(self):
        args = self.parser.parse_args(["status"])
        assert args.command == "status"
        assert hasattr(args, "func")

    def test_version_subcommand(self):
        args = self.parser.parse_args(["version"])
        assert args.command == "version"

    def test_machines_default_action(self):
        args = self.parser.parse_args(["machines"])
        assert args.command == "machines"
        assert args.action == "list"

    def test_machines_add(self):
        args = self.parser.parse_args(["machines", "add"])
        assert args.action == "add"

    def test_machines_remove(self):
        args = self.parser.parse_args(["machines", "remove"])
        assert args.action == "remove"

    def test_deploy_requires_name(self):
        args = self.parser.parse_args(["deploy", "web-prod"])
        assert args.command == "deploy"
        assert args.name == "web-prod"

    def test_deploy_db_requires_name(self):
        args = self.parser.parse_args(["deploy-db", "db-server"])
        assert args.command == "deploy-db"
        assert args.name == "db-server"

    def test_generate(self):
        args = self.parser.parse_args(["generate"])
        assert args.command == "generate"

    def test_diff(self):
        args = self.parser.parse_args(["diff"])
        assert args.command == "diff"

    def test_deploy_otel_all(self):
        args = self.parser.parse_args(["deploy-otel"])
        assert args.command == "deploy-otel"
        assert args.name is None

    def test_deploy_otel_single(self):
        args = self.parser.parse_args(["deploy-otel", "web-prod"])
        assert args.name == "web-prod"

    def test_warden_enroll(self):
        args = self.parser.parse_args(["warden-enroll", "web-prod"])
        assert args.command == "warden-enroll"
        assert args.name == "web-prod"
        assert args.no_restart is False
        assert args.force is False

    def test_warden_enroll_flags(self):
        args = self.parser.parse_args(["warden-enroll", "db-prod", "--no-restart", "--force"])
        assert args.no_restart is True
        assert args.force is True

    def test_no_command_defaults_none(self):
        args = self.parser.parse_args([])
        assert args.command is None


class TestVersion:
    def test_version_string(self):
        assert "2.0.0" in __version__
