from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import yaml


def _write_state(path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "dwlabbind/v1",
                "server": {
                    "name": "dns-01",
                    "resolver_policy": {
                        "recursion_enabled": False,
                        "allow_query": ["any"],
                        "allow_recursion": [],
                        "forwarders": [],
                        "forward_mode": "first",
                    },
                },
                "tsig_keys": [],
                "zones": [],
                "views": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def test_runner_desired_state_plan_returns_machine_readable_result(tmp_path: Path) -> None:
    state = tmp_path / "state.yaml"
    _write_state(state)

    repository_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        [
            str(repository_root / "src"),
            str(repository_root.parent / "dwlabbasicpy" / "src"),
        ]
    )
    completed = subprocess.run(
        [sys.executable, "-m", "dwlabbind.runner", "desired-state-plan", "--state", str(state)],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"can_apply": True, "issues": []}


def test_runner_rpz_add_persists_a_typed_rule(tmp_path: Path) -> None:
    state = tmp_path / "state.yaml"
    _write_state(state)
    document = yaml.safe_load(state.read_text(encoding="utf-8"))
    document["response_policies"] = [
        {"name": "internal-host-overrides", "zone_name": "rpz.internal.dw-lab", "enabled": True, "rules": []}
    ]
    state.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    repository_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join([str(repository_root / "src"), str(repository_root.parent / "dwlabbasicpy" / "src")])
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "dwlabbind.runner",
            "rpz",
            "add",
            "--state",
            str(state),
            "--policy",
            "internal-host-overrides",
            "--query-name",
            "t-com.dw-lab.com",
            "--record",
            "A=192.168.2.31",
        ],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    persisted = yaml.safe_load(state.read_text(encoding="utf-8"))
    assert persisted["response_policies"][0]["rules"] == [
        {"query_name": "t-com.dw-lab.com", "action": "answer", "records": [{"type": "A", "value": "192.168.2.31"}]}
    ]


def test_runner_rpz_policy_create_and_fixed_host_add_follow_domain_convention(tmp_path: Path) -> None:
    state = tmp_path / "state.yaml"
    _write_state(state)
    repository_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join([str(repository_root / "src"), str(repository_root.parent / "dwlabbasicpy" / "src")])

    for command in (
        ["policy-create", "--state", str(state), "--domain-name", "dw-lab.com"],
        [
            "fixed-host-add",
            "--state",
            str(state),
            "--policy",
            "dw-lab.com-overrides",
            "--hostname",
            "cmkdev",
            "--ip-address",
            "192.168.2.31",
        ],
    ):
        completed = subprocess.run(
            [sys.executable, "-m", "dwlabbind.runner", "rpz", *command],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr

    persisted = yaml.safe_load(state.read_text(encoding="utf-8"))
    assert persisted["response_policies"] == [
        {
            "name": "dw-lab.com-overrides",
            "zone_name": "rpz.dw-lab.com-overrides",
            "enabled": True,
            "rules": [
                {
                    "query_name": "cmkdev.dw-lab.com",
                    "action": "answer",
                    "records": [{"type": "A", "value": "192.168.2.31"}],
                }
            ],
        }
    ]
