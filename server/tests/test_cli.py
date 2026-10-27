"""§7 – CLI commands (commands/*.py) via Flask's test CLI runner."""
from models import Host, Image


def test_hosts_add(cli):
    res = cli.invoke(args=["hosts", "add", "myhost", "--address", "http://h"])
    assert res.exit_code == 0
    h = Host.query.filter_by(name="myhost").first()
    assert h is not None
    assert h.address == "http://h/"   # trailing slash added
    assert len(h.token) == 32         # auto-generated when not provided


def test_hosts_add_with_token(cli):
    cli.invoke(args=["hosts", "add", "withtok", "--address", "http://h", "--token", "secret"])
    assert Host.query.filter_by(name="withtok").first().token == "secret"


def test_hosts_add_duplicate_is_rejected(cli):
    cli.invoke(args=["hosts", "add", "dup", "--address", "http://d"])
    res = cli.invoke(args=["hosts", "add", "dup", "--address", "http://d"])
    assert "already exist" in res.output
    assert Host.query.filter_by(name="dup").count() == 1


def test_hosts_edit_updates_only_given_fields(cli):
    cli.invoke(args=["hosts", "add", "e", "--address", "http://e", "--token", "old"])
    cli.invoke(args=["hosts", "edit", "e", "--token", "new"])
    host = Host.query.filter_by(name="e").first()
    assert host.token == "new"
    assert host.address == "http://e/"  # unchanged


def test_hosts_edit_address_and_enabled(cli):
    cli.invoke(args=["hosts", "add", "ea", "--address", "http://old"])
    cli.invoke(args=["hosts", "edit", "ea", "--address", "http://changed", "--enabled", "False"])
    host = Host.query.filter_by(name="ea").first()
    assert host.address == "http://changed"
    assert host.enabled is False


def test_hosts_edit_missing(cli):
    res = cli.invoke(args=["hosts", "edit", "nope", "--token", "x"])
    assert "does not exist" in res.output


def test_hosts_rm(cli):
    cli.invoke(args=["hosts", "add", "r", "--address", "http://r"])
    cli.invoke(args=["hosts", "rm", "r"])
    assert Host.query.filter_by(name="r").first() is None


def test_hosts_rm_missing(cli):
    res = cli.invoke(args=["hosts", "rm", "nope"])
    assert "not found" in res.output.lower()


def test_ls_commands_run(cli):
    cli.invoke(args=["hosts", "add", "l", "--address", "http://l"])
    assert cli.invoke(args=["hosts", "ls"]).exit_code == 0
    assert cli.invoke(args=["images", "ls"]).exit_code == 0
    assert cli.invoke(args=["containers", "ls"]).exit_code == 0


def test_images_ls_renders_scanner_summaries(cli):
    # exercises parse_trivy_to_str / parse_xeol_to_str in the CLI rendering path
    Image(name="nginx", repo_digest="nginx@sha256:a",
          status_trivy={"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL"}]}]},
          status_xeol={"matches": []}).save()
    res = cli.invoke(args=["images", "ls"])
    assert res.exit_code == 0
    assert "nginx" in res.output
