# VukZero Agent Permission System

The VukZero permission system is the Layer-1 Brain-vs-Hands enforcement
boundary. The LLM-facing brain may propose actions, but the hands that touch
files, network sinks, logs, wallets, identity material, seedbox controls, or
reputation state must pass through the reference monitor.

For the main OpenClaw runtime, permission enforcement is enabled by default.
You can also force it with `VUKZERO_PERMISSION_SYSTEM=enabled` before
constructing tools with `agent.tools.build_tools(agent)`. Set
`AgentConfig(permissions_enabled=False)` or `VUKZERO_PERMISSION_SYSTEM=disabled`
only for intentional baseline or compatibility runs. The returned registry
routes all tool dispatch through `ToolBroker` and checks final assistant text
for protected canaries before returning it from the tool loop.

Main components:

- `default_policy.yaml`: deny-by-default policy rules.
- `ResourceRegistry`: maps resource handles to security labels.
- `CapabilityStore`: stores scoped, revocable task permissions.
- `PermissionEngine`: evaluates policy, capabilities, and validators.
- `ToolBroker`: dispatches tools only after authorization.
- `EgressGuard`: blocks protected canaries and secret-shaped material.
- `proxies.py`: narrow proxy APIs for privileged resources.
- `DecisionLog`: local audit trail for permission decisions.

## Add A Protected Resource

Register a resource handle instead of exposing a raw path:

```python
registry.register(Resource("identity_key", "secret.identity"))
```

Unknown resources fail closed.

## Add A Tool

Register the raw callable with the broker and describe how to resolve its
resource:

```python
broker.register_tool(
    "read_resource",
    read_resource,
    action="read",
    resource_resolver=lambda args: args["resource_id"],
)
```

## Add A Policy Rule

Add a rule to `default_policy.yaml`. Rules specify role, action, resource label,
effect, optional capability requirement, validators, and optional proxy.

## Issue A Capability

```python
store.issue(Capability(
    capability_id="cap_task_001_report",
    subject_id="agent_A0",
    allowed_action="write",
    resource_label="external.report_sink",
    task_id="task_001",
    expires_at_round=12,
))
```

## Example

```python
subject = Subject(subject_id="agent_A0", role="normal_agent")

await broker.call_tool(
    subject=subject,
    tool_name="read_resource",
    args={"resource_id": "task_input_001"},
    task_id="task_001",
)
```

Denied direct secret access:

```python
await broker.call_tool(
    subject=subject,
    tool_name="read_identity_key",
    args={"resource_id": "identity_key"},
)
```

Run tests:

```bash
python -m pytest tests/test_permissions_*.py -q
```
