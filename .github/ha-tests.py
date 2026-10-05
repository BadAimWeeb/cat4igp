"""Run optional HA subprocess checks with Cargo's actual emitted executables."""

import json
import os
from pathlib import Path
import subprocess


os.chdir(Path(__file__).resolve().parents[1])


def executable(command, name, test):
    result = subprocess.run(
        command + ["--message-format=json"], check=True, text=True, stdout=subprocess.PIPE
    )
    paths = {
        artifact["executable"]
        for line in result.stdout.splitlines()
        if (artifact := json.loads(line)).get("reason") == "compiler-artifact"
        and artifact["target"]["name"] == name
        and artifact["profile"]["test"] == test
        and artifact.get("executable")
    }
    if len(paths) != 1:
        raise RuntimeError(f"Expected one Cargo executable for {name}, found {len(paths)}")
    return paths.pop()


env = os.environ.copy()
env["CAT4IGP_CLIENT_TEST_BINARY"] = executable(
    ["cargo", "test", "--locked", "-p", "cat4igp-client", "--no-run"],
    "cat4igp-client", True,
)
env["CAT4IGP_RECOVERY_TEST_BINARY"] = executable(
    ["cargo", "build", "--locked", "-p", "cat4igp-server"],
    "cat4igp-server", False,
)
# ponytail: existing bounded unprivileged fixtures; not WireGuard traffic or powerloss.
for test in (
    "cluster::tests::three_process_leader_kill_recovers_invites",
    "raft_storage::tests::offline_recovery_verifies_and_restores_fresh_application_without_local_identity",
):
    subprocess.run(
        ["cargo", "test", "--locked", "-p", "cat4igp-server", test,
         "--", "--exact", "--nocapture"],
        env=env, check=True, timeout=180,
    )