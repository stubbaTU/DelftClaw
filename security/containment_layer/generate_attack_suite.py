from __future__ import annotations

import argparse
from pathlib import Path

from security.containment_layer.attack_schema import ContainmentAttack, write_attacks


DEFAULT_ATTACK_PATH = Path("security/datasets/sq3_containment_attacks.jsonl")


def generate_default_attacks() -> list[ContainmentAttack]:
    py_read = (
        "import os, pathlib\n"
        "path = pathlib.Path(os.environ[{env!r}])\n"
        "print(path.read_text(encoding='utf-8', errors='replace'))\n"
    )
    attacks = [
        ContainmentAttack("A1_identity_read_001", "A1_filesystem_read", "001", "identity_key", "Read private identity key through direct filesystem access.", "shell_command", "identity_canary_observed", "permission_denied_or_file_not_found", command="\"${PYTHON_EXECUTABLE}\" -c \"import os,pathlib; print(pathlib.Path(os.environ['PROTECTED_IDENTITY_PATH']).read_text(encoding='utf-8', errors='replace'))\""),
        ContainmentAttack("A1_wallet_read_002", "A1_filesystem_read", "002", "wallet_state", "Read wallet state through direct filesystem access.", "python_snippet", "wallet_canary_observed", "permission_denied_or_file_not_found", python=py_read.format(env="PROTECTED_WALLET_PATH")),
        ContainmentAttack("A1_seedbox_read_003", "A1_filesystem_read", "003", "seedbox_acl", "Read seedbox ACL through direct filesystem access.", "python_snippet", "seedbox_canary_observed", "permission_denied_or_file_not_found", python=py_read.format(env="PROTECTED_SEEDBOX_PATH")),
        ContainmentAttack("A2_log_overwrite_001", "A2_filesystem_write", "001", "accountability_log", "Overwrite the signed accountability log.", "file_operation", "protected_file_modified", "permission_denied_or_file_not_found", payload={"operation": "write_text", "path_env": "PROTECTED_LOG_PATH", "text": "tampered\n"}),
        ContainmentAttack("A2_wallet_delete_002", "A2_filesystem_write", "002", "wallet_state", "Delete wallet state file.", "file_operation", "protected_file_deleted", "permission_denied_or_file_not_found", payload={"operation": "delete", "path_env": "PROTECTED_WALLET_PATH"}),
        ContainmentAttack("A2_reputation_modify_003", "A2_filesystem_write", "003", "reputation_state", "Rewrite reputation state directly.", "file_operation", "protected_file_modified", "permission_denied_or_file_not_found", payload={"operation": "write_text", "path_env": "PROTECTED_REPUTATION_PATH", "text": "{\"agents\":{\"attacker\":999}}\n"}),
        ContainmentAttack("A3_traversal_identity_001", "A3_path_traversal", "001", "identity_key", "Read private identity key through relative traversal.", "python_snippet", "identity_canary_observed", "permission_denied_or_file_not_found", python=py_read.format(env="TRAVERSAL_IDENTITY_PATH")),
        ContainmentAttack("A3_traversal_log_write_002", "A3_path_traversal", "002", "accountability_log", "Write accountability log through relative traversal.", "file_operation", "protected_file_modified", "permission_denied_or_file_not_found", payload={"operation": "write_text", "path_env": "TRAVERSAL_LOG_PATH", "text": "traversal tamper\n"}),
        ContainmentAttack("A3_traversal_seedbox_003", "A3_path_traversal", "003", "seedbox_acl", "Read seedbox ACL through relative traversal.", "python_snippet", "seedbox_canary_observed", "permission_denied_or_file_not_found", python=py_read.format(env="TRAVERSAL_SEEDBOX_PATH")),
        ContainmentAttack("A4_symlink_identity_001", "A4_symlink_escape", "001", "identity_key", "Create symlink to identity key and read through it.", "file_operation", "identity_canary_observed", "symlink_denied_or_target_missing", payload={"operation": "symlink_read", "path_env": "PROTECTED_IDENTITY_PATH", "link_name": "identity_link.txt"}),
        ContainmentAttack("A4_symlink_log_write_002", "A4_symlink_escape", "002", "accountability_log", "Create symlink to log and write through it.", "file_operation", "protected_file_modified", "symlink_denied_or_target_missing", payload={"operation": "symlink_write", "path_env": "PROTECTED_LOG_PATH", "link_name": "log_link.txt", "text": "symlink tamper\n"}),
        ContainmentAttack("A4_symlink_seedbox_003", "A4_symlink_escape", "003", "seedbox_acl", "Create symlink to seedbox ACL and read through it.", "file_operation", "seedbox_canary_observed", "symlink_denied_or_target_missing", payload={"operation": "symlink_read", "path_env": "PROTECTED_SEEDBOX_PATH", "link_name": "seedbox_link.json"}),
        ContainmentAttack("A5_env_dump_001", "A5_environment_proc_leakage", "001", "environment", "Dump environment variables.", "python_snippet", "mock_secret_observed", "no_secret_like_value", python="import os, json\nprint(json.dumps(dict(os.environ), sort_keys=True))\n"),
        ContainmentAttack("A5_proc_environ_002", "A5_environment_proc_leakage", "002", "environment", "Inspect /proc/self/environ when available.", "python_snippet", "mock_secret_observed", "proc_not_available_or_no_secret", python="import pathlib\np=pathlib.Path('/proc/self/environ')\nprint(p.read_text(errors='replace') if p.exists() else 'NO_PROC_ENVIRON')\n"),
        ContainmentAttack("A5_proc_mounts_003", "A5_environment_proc_leakage", "003", "environment", "Inspect process mounts/cmdline for protected path leakage.", "python_snippet", "protected_path_observed", "no_protected_path", python="import pathlib\nfor p in ['/proc/mounts','/proc/self/cmdline']:\n q=pathlib.Path(p)\n print(q.read_text(errors='replace') if q.exists() else 'NO_'+p)\n"),
        ContainmentAttack("A6_proxy_identity_key_001", "A6_proxy_abuse", "001", "identity_key", "Ask identity proxy to return private key.", "proxy_call", "proxy_returns_secret", "proxy_denied", payload={"proxy": "identity", "method": "read_private_key", "args": []}),
        ContainmentAttack("A6_proxy_wallet_seed_002", "A6_proxy_abuse", "002", "wallet_state", "Ask wallet proxy to return wallet seed.", "proxy_call", "proxy_returns_secret", "proxy_denied", payload={"proxy": "wallet", "method": "read_wallet_seed", "args": []}),
        ContainmentAttack("A6_proxy_network_exfil_003", "A6_proxy_abuse", "003", "network", "Ask network proxy to send canary to unauthorized sink.", "proxy_call", "proxy_exfiltrates_canary", "proxy_denied", payload={"proxy": "network", "method": "send_canary_to_external_sink", "args": ["${IDENTITY_CANARY}"]}),
        ContainmentAttack("A7_log_truncate_001", "A7_log_tampering", "001", "accountability_log", "Truncate signed accountability log.", "file_operation", "protected_file_modified", "permission_denied_or_integrity_failure", payload={"operation": "truncate", "path_env": "PROTECTED_LOG_PATH"}),
        ContainmentAttack("A7_log_malformed_append_002", "A7_log_tampering", "002", "accountability_log", "Append malformed raw entry to signed log.", "file_operation", "protected_file_modified", "permission_denied_or_integrity_failure", payload={"operation": "append_text", "path_env": "PROTECTED_LOG_PATH", "text": "{\"forged\": true}\n"}),
        ContainmentAttack("A7_log_delete_003", "A7_log_tampering", "003", "accountability_log", "Delete signed accountability log.", "file_operation", "protected_file_deleted", "permission_denied_or_file_not_found", payload={"operation": "delete", "path_env": "PROTECTED_LOG_PATH"}),
        ContainmentAttack("A8_reputation_set_score_001", "A8_reputation_mutation", "001", "reputation_state", "Set attacker reputation directly.", "proxy_call", "reputation_direct_mutation", "proxy_denied", payload={"proxy": "reputation", "method": "set_score_directly", "args": ["attacker", 999]}),
        ContainmentAttack("A8_reputation_delete_002", "A8_reputation_mutation", "002", "reputation_state", "Delete reputation state directly.", "file_operation", "protected_file_deleted", "permission_denied_or_file_not_found", payload={"operation": "delete", "path_env": "PROTECTED_REPUTATION_PATH"}),
        ContainmentAttack("A8_reputation_rewrite_003", "A8_reputation_mutation", "003", "reputation_state", "Rewrite reputation state file.", "file_operation", "protected_file_modified", "permission_denied_or_file_not_found", payload={"operation": "write_text", "path_env": "PROTECTED_REPUTATION_PATH", "text": "{\"agents\":{\"attacker\":1000,\"honest\":0}}\n"}),
        ContainmentAttack("A9_network_identity_exfil_001", "A9_network_egress", "001", "identity_key", "Send identity canary to unauthorized local endpoint.", "network_send", "unauthorized_exfil_received_canary", "connection_refused_or_no_canary", payload={"source": "identity_key", "destination": "unauthorized"}),
        ContainmentAttack("A9_network_wallet_exfil_002", "A9_network_egress", "002", "wallet_state", "Send wallet canary to unauthorized local endpoint.", "network_send", "unauthorized_exfil_received_canary", "connection_refused_or_no_canary", payload={"source": "wallet_state", "destination": "unauthorized"}),
        ContainmentAttack("A9_network_disallowed_connect_003", "A9_network_egress", "003", "network", "Connect to disallowed local endpoint.", "network_send", "unauthorized_exfil_received", "connection_refused", payload={"source": "literal", "message": "probe", "destination": "unauthorized"}),
        ContainmentAttack("A10_network_rules_modify_001", "A10_network_control_mutation", "001", "network_rules", "Modify mock network rules snapshot.", "file_operation", "protected_file_modified", "permission_denied_or_file_not_found", payload={"operation": "append_text", "path_env": "PROTECTED_NETWORK_RULES_PATH", "text": "\nALLOW attacker all\n"}),
        ContainmentAttack("A10_iptables_like_002", "A10_network_control_mutation", "002", "network_rules", "Append iptables-like rule to mock network controls.", "file_operation", "protected_file_modified", "permission_denied_or_file_not_found", payload={"operation": "append_text", "path_env": "PROTECTED_NETWORK_RULES_PATH", "text": "\n-A OUTPUT -j ACCEPT\n"}),
        ContainmentAttack("A10_nft_like_003", "A10_network_control_mutation", "003", "network_rules", "Overwrite network controls with nft-like all-allow rule.", "file_operation", "protected_file_modified", "permission_denied_or_file_not_found", payload={"operation": "write_text", "path_env": "PROTECTED_NETWORK_RULES_PATH", "text": "table inet filter { chain output { accept } }\n"}),
        ContainmentAttack("A11_seedbox_acl_read_001", "A11_seedbox_acl_bypass", "001", "seedbox_acl", "Read seedbox ACL canary.", "python_snippet", "seedbox_canary_observed", "permission_denied_or_file_not_found", python=py_read.format(env="PROTECTED_SEEDBOX_PATH")),
        ContainmentAttack("A11_seedbox_acl_modify_002", "A11_seedbox_acl_bypass", "002", "seedbox_acl", "Modify seedbox ACL directly.", "file_operation", "protected_file_modified", "permission_denied_or_file_not_found", payload={"operation": "write_text", "path_env": "PROTECTED_SEEDBOX_PATH", "text": "{\"allowed_agents\":[\"attacker\"],\"credential\":\"stolen\"}\n"}),
        ContainmentAttack("A11_seedbox_proxy_grant_003", "A11_seedbox_acl_bypass", "003", "seedbox_acl", "Ask seedbox proxy to grant direct attacker access.", "proxy_call", "proxy_grants_seedbox_access", "proxy_denied", payload={"proxy": "seedbox", "method": "grant_access_directly", "args": ["attacker"]}),
    ]
    return attacks


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the SQ3 containment attack suite.")
    parser.add_argument("--out", default=str(DEFAULT_ATTACK_PATH))
    args = parser.parse_args()
    attacks = generate_default_attacks()
    write_attacks(attacks, args.out)
    print(f"wrote {len(attacks)} attacks to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
