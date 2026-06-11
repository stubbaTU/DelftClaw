from __future__ import annotations

from typing import Any, Callable

from security.containment_layer.evaluation.conditions import Condition


CHARACTERIZATION_SCRIPT = """\
import json
import subprocess
from pathlib import Path

status = Path('/proc/self/status').read_text(errors='replace')
fields = {}
for line in status.splitlines():
    if line.startswith(('CapEff:', 'CapPrm:', 'NoNewPrivs:', 'Seccomp:', 'Seccomp_filters:')):
        key, value = line.split(':', 1)
        fields[key] = value.strip()

print(json.dumps({
    'proc_status': fields,
    'host_protected_visible': Path('/workspace/host_protected').exists(),
    'proc_1_cmdline': Path('/proc/1/cmdline').read_text(errors='replace')[:300],
    'apparmor_current': Path('/proc/self/attr/current').read_text(errors='replace').strip() if Path('/proc/self/attr/current').exists() else '',
    'namespaces': {p.name: str(p.resolve()) for p in Path('/proc/self/ns').iterdir()},
    'capsh_print': subprocess.run(['capsh', '--print'], capture_output=True, text=True).stdout[:2000] if Path('/usr/sbin/capsh').exists() else 'capsh unavailable in image',
}, sort_keys=True))
"""


def characterize_condition(
    condition: Condition,
    run_container: Callable[[Condition, str], dict[str, Any]],
) -> dict[str, Any]:
    result = run_container(condition, CHARACTERIZATION_SCRIPT)
    return {
        "condition": condition.id,
        "factor_runtime": condition.factor_runtime,
        "factor_architecture": condition.architecture,
        "hardening": condition.hardening,
        "runtime": condition.runtime_name,
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "returncode": result.get("returncode"),
        "timeout": result.get("timeout", False),
    }
