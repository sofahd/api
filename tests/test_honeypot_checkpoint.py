"""
Regression tests for the emulated CVE-2024-24919 (Check Point) file-read endpoint.

`serve_checkpoint_endpoint` used to run `cat {attacker_path}` via shell=True on the host
-- a real RCE / honeypot escape. These tests pin the hardened behaviour: the emulation
still returns convincing fake files, but the request is resolved strictly inside the
planted sandbox and no shell is ever involved.
"""
import json
import os

import pytest

import honeypot.honeypot as hp
from honeypot.honeypot import Honeypot

HERE = os.path.dirname(__file__)
SANDBOX = os.path.realpath(os.path.join(HERE, "..", "data", "sandbox"))


class FakeLogger:
    def __init__(self):
        self.events = []

    def log(self, event_id, content, ip, port):
        self.events.append(event_id)

    def warn(self, message, method, ip, port):
        self.events.append("warn:" + method)


@pytest.fixture
def pot(tmp_path, monkeypatch):
    monkeypatch.setattr(hp, "SANDBOX_ROOT", SANDBOX)
    answerset = tmp_path / "answerset.json"
    answerset.write_text(json.dumps({"endpoints": {}, "placeholders": {}}))
    logger = FakeLogger()
    instance = Honeypot(logger=logger, answerset_path=str(answerset))
    instance._test_logger = logger
    return instance


def serve(pot, payload):
    response = pot.serve_checkpoint_endpoint(
        answer_dict={}, ip="9.9.9.9", port=4444, content=payload, path="/clients/MyCRL"
    )
    return response.get_data(as_text=True)


def test_cve_payload_serves_planted_shadow(pot):
    planted = open(os.path.join(SANDBOX, "etc", "shadow")).read()
    assert serve(pot, "aCSHELL/../../../../../../etc/shadow") == planted


def test_cve_payload_serves_planted_passwd(pot):
    planted = open(os.path.join(SANDBOX, "etc", "passwd")).read()
    out = serve(pot, "aCSHELL/../../../etc/passwd")
    assert out == planted
    assert "Administrator" in out  # it's our planted fake, not the host's passwd


@pytest.mark.parametrize(
    "payload",
    [
        "aCSHELL/etc/passwd; cat /etc/shadow",
        "aCSHELL/$(id)",
        "aCSHELL/etc/passwd`id`",
        "aCSHELL/etc/passwd\ncat /etc/hostname",
        "aCSHELL/etc/passwd | whoami",
        "aCSHELL/etc/passwd & sleep 5",
    ],
)
def test_injection_payloads_are_inert(pot, payload):
    # If a shell were still involved, these would execute or error differently;
    # in the sandboxed reader they are just non-existent path segments.
    assert serve(pot, payload) == "Broken pipe"


def test_host_only_path_is_not_leaked(pot):
    # /etc/hostname exists on the host but not in the sandbox -> must never be served.
    assert serve(pot, "aCSHELL/../../../etc/hostname") == "Broken pipe"


def test_miss_and_empty_return_broken_pipe(pot):
    assert serve(pot, "aCSHELL/etc/nonexistent") == "Broken pipe"
    assert serve(pot, "aCSHELL") == "Broken pipe"


def test_no_shell_imported_and_attempt_is_logged(pot):
    assert not hasattr(hp, "subprocess"), "the module must not import subprocess anymore"
    serve(pot, "aCSHELL/../../../etc/passwd")
    assert "api.honeypot.checkpoint_attempt" in pot._test_logger.events
