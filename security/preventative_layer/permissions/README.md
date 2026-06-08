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
- `effects.py`: generic three-class tool classification with an effect-safe
  default.
- `provenance.py`: trusted-task and runtime value-provenance tracking.
- `ResourceRegistry`: maps resource handles to security labels.
- `CapabilityStore`: stores scoped, revocable task permissions.
- `PermissionEngine`: evaluates policy, capabilities, and validators.
- `ToolBroker`: dispatches tools only after authorization.
- `EgressGuard`: blocks protected canaries and secret-shaped material.
- `proxies.py`: narrow proxy APIs for privileged resources.
- `DecisionLog`: local audit trail for permission decisions.

SQ1 uses a separate generic provenance policy built by
`build_provenance_policy()`. It allows reads, but requires both a task-scoped
capability and provenance validation for every `EFFECT`.

Unknown tools are not assumed safe. They default to `EFFECT`, so they need
explicit task authorization and clean arguments.

Read tools default to `READ_CONTENT`. Mark a source `READ_AUTHORITATIVE` only
after auditing that its identifier fields cannot be attacker-written. Even
then, identifiers are promoted only when the lookup inputs are trusted.

All effect arguments require trusted provenance by default. Generated control
arguments require an explicit audited `neutral_args` annotation. Public or
broadcast effects are denied after untrusted reads unless trusted metadata
explicitly approves the flow.

## Add A Protected Resource

Register a resource handle instead of exposing a raw path:

```python
registry.register(Resource("identity_key", "secret.identity"))
```

Unknown resources fail closed.

## Add A Tool

Prefer attaching trusted security metadata to the tool:

```python
ToolSecuritySpec(
    name="lookup_directory",
    annotations={"effect_class": "read_authoritative"},
)
```

Without an annotation, classification is inferred conservatively from trusted
tool metadata. Read-like tools default to untrusted content reads; ambiguous
tools default to `EFFECT`.

Example effect metadata:

```python
ToolSecuritySpec(
    name="create_calendar_event",
    annotations={
        "neutral_args": ["title", "start_time", "end_time"],
        "max_uses": 1,
    },
)
```

For external catalogs whose tool objects cannot carry annotations, provide an
audited JSON overlay to the SQ1 runner:

```json
{
  "search_contacts_by_name": {
    "effect_class": "read_authoritative",
    "authoritative_lookup_args": ["name"]
  },
  "create_calendar_event": {
    "neutral_args": ["title", "start_time", "end_time"],
    "max_uses": 1
  },
  "send_money": {
    "bind_task_literals": {
      "amount": "amount"
    }
  }
}
```

```bash
python -m security.preventative_layer.agentdojo_runner \
  ... \
  --trusted-tool-metadata security/preventative_layer/trusted_tool_metadata.json
```

The overlay is trusted deployment configuration and must be reviewed. Never
mark an episode-writable store authoritative.

`authoritative_lookup_args` is mandatory for authoritative reads that accept
arguments. Only those reviewed lookup-key arguments gate identifier promotion.
Without this metadata, an argument-bearing authoritative read promotes no
output.

`bind_task_literals` binds task literals to capability argument positions.
For example, an explicitly requested `$100` may authorize `amount=100.00`, but
does not globally make the value `100` trusted for another argument or tool.

Before a full AgentDojo run, audit likely utility-ceiling tasks on the VPS:

```bash
python -m security.preventative_layer.audit_agentdojo_tasks \
  --benchmark-version v1.2.2 \
  --suites workspace slack banking travel \
  --out results/sq1_task_shape_audit
```

The audit flags likely multi-hop-into-effect and read-then-broadcast tasks for
manual review. It is a heuristic upper bound, not an AgentDojo utility score.

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
