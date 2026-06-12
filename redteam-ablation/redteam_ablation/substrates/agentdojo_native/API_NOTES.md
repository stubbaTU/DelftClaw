# agentdojo 0.1.35 — installed-API survey (2026-06-10)

Ground truth for the Substrate-2 build. Every claim read from the installed source under
`.venv/Lib/site-packages/agentdojo/`. **Code against THIS file, not the paper summary.**
(Requires-Python >= 3.10; venv runs CPython 3.13.)

## 1. BasePipelineElement (`agentdojo/agent_pipeline/base_pipeline_element.py`)

Import: `from agentdojo.agent_pipeline import BasePipelineElement` (re-exported in
`agent_pipeline/__init__.py`).

```python
class BasePipelineElement(abc.ABC):
    name: str | None = None
    @abc.abstractmethod
    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]: ...
```

Every element receives and returns the same 5-tuple. State flows through `messages` and `env`;
`extra_args` is the cross-element scratch dict. Elements that "add" a message return
`[*messages, new_message]`.

## 2. Pipeline composition (`agent_pipeline/agent_pipeline.py`, `tool_execution.py`, `basic_elements.py`)

- `AgentPipeline(elements: Iterable[BasePipelineElement])` — runs elements in order; is itself a
  `BasePipelineElement`. Has `.name` (set it; the benchmark's log-caching keys on it).
- Canonical agent: `AgentPipeline([SystemMessage(...), InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), llm])])`.
- `ToolsExecutionLoop(elements, max_iters=15)` — loops its elements while the last message is an
  assistant message with non-empty `tool_calls`.
- `ToolsExecutor.query` (tool_execution.py:46) — **THE SEAM**. For each `tool_call` in
  `messages[-1]["tool_calls"]`: skips empty/unknown function names (appends a
  `ChatToolResultMessage` with the `error=` field set), else calls
  `runtime.run_function(env, tool_call.function, tool_call.args)` and appends a
  `ChatToolResultMessage(role="tool", content=[text block], tool_call_id, tool_call, error)`.
- **Defense insertion precedent**: defenses that vet tool calls live INSIDE the
  `ToolsExecutionLoop`, before/around the executor (`pi_detector.py` sits between executor and
  llm; `OpenAILLMToolFilter` filters runtime functions before the llm). Our
  `IntegrityDefenseElement` REPLACES `ToolsExecutor` in the loop: same iteration contract, but
  each call is dispatched through our `Dispatcher` first.
- Denial convention: a `ChatToolResultMessage` with `error="<reason>"` and empty/short content —
  identical to their unknown-tool path. The episode continues; the model sees the error.
- `AbortAgentError` (`agent_pipeline/errors.py`) exists for hard-abort defenses;
  `run_task_with_pipeline` catches it and salvages env+messages. We do NOT use it (deny-and-continue).

## 3. FunctionsRuntime (`agentdojo/functions_runtime.py`)

- `FunctionsRuntime(functions: Sequence[Function] = [])`; `.functions: dict[str, Function]`.
- `register_function(fn_or_Function)` — plain callables need a docstring with short description +
  per-arg descriptions (parsed via docstring_parser; ValueError otherwise) and type hints
  (pydantic input model is generated). `Depends("attr")`-annotated params are injected from env,
  invisible to the model.
- `run_function(env, function: str, kwargs, raise_on_error=False) -> tuple[FunctionReturnType, str | None]`
  — returns `(result, error)`; error format `'ErrorType: ErrorMessage'`; unknown tool →
  `("", "ToolNotFoundError: ...")`; pydantic arg validation → `("", "ValidationError: ...")`.
- `FunctionCall` (pydantic): `.function: str`, `.args: MutableMapping`, `.id: str | None`,
  `.placeholder_args` (ground-truth only).

## 4. Task suites (`task_suite/task_suite.py`, `task_suite/load_suites.py`)

- `get_suite(benchmark_version: str, suite_name: str) -> TaskSuite`;
  `get_suites(version) -> dict`. Versions registered: `"v1"`, `"v1.1"`, `"v1.1.1"`, `"v1.1.2"`,
  `"v1.2"`, `"v1.2.1"`, `"v1.2.2"`. Suite names: `workspace`, `travel`, `banking`, `slack`.
- `suite.user_tasks` / `suite.injection_tasks` → `dict[task_id, task]` resolved per the suite's
  `benchmark_version` (task ids like `"user_task_0"`, `"injection_task_5"`).
- **Counts are version-dependent** (v1_1/v1_2 modules register new/updated tasks at import).
  Workspace v1 source declares 33 `UserTaskN` classes and **6 `InjectionTaskN` (0–5)** — the 6
  matches F9's behaviour-control count. The paper's 97-benign total is the original-release
  number; the runner MUST derive counts from `len(suite.user_tasks)` at run time and record the
  pinned `benchmark_version` in every record. Sub-decision: pin `"v1"` (paper-comparable) vs
  `"v1.2.2"` (bug-fixed) — flag to Lucas before any metered run.
- `register_suite(suite, version)` (load_suites.py) — registry is module-global; for tests,
  either avoid registration entirely (construct `TaskSuite` directly and pass it around) or use
  a unique suite name per test to dodge collisions.
- Custom suite: `TaskSuite(name, environment_type, tools: list[Function], data_path=None, benchmark_version=(1,0,0))`
  + `@suite.register_user_task` / `@suite.register_injection_task` class decorators. Task classes
  MUST be named `UserTask<N>` / `InjectionTask<N>` (regex-enforced). User tasks subclass
  `BaseUserTask` (`base_tasks.py`): need `PROMPT`, `utility(model_output, pre_env, post_env) -> bool`
  (and/or `utility_from_traces`), `ground_truth(pre_env) -> list[FunctionCall]`. Injection tasks
  subclass `BaseInjectionTask`: `GOAL`, `security(...)`/`security_from_traces`, `ground_truth`.

## 5. Running tasks (`task_suite.py:339 run_task_with_pipeline`)

```python
suite.run_task_with_pipeline(
    agent_pipeline, user_task, injection_task, injections,
    runtime_class=FunctionsRuntime, environment=None, verbose=False,
) -> tuple[bool, bool]   # (utility, security)
```

- Benign mode: `injection_task=None, injections={}` → returns `(utility, True)`.
- If `environment=None` it loads the suite's `environment.yaml` (+ injects); **passing
  `environment=` explicitly SKIPS the data files** → offline stub suites need no yaml on disk.
- It builds `runtime = runtime_class(suite.tools)` itself, takes `pre_environment` deep-copy,
  prompts with `user_task.PROMPT`, calls `agent_pipeline.query(prompt, runtime, task_environment)`
  (retries ×3 if model output None), then evaluates utility/security itself.
- Utility/security checkers receive `functions_stack_trace_from_messages(messages)` = **all
  assistant-PROPOSED tool calls** (not just executed ones). Env-state checks see only executed
  effects. Honesty note for the paper: a denied call may still appear in `*_from_traces` checks.
- Attack runs (`benchmark.py:41 run_task_with_injection_tasks`): `injections = attack.attack(user_task, injection_task)`;
  full benchmark iterates ALL injection tasks per user task. We instead run our pre-registered
  pairing (one user task per injection task — F9: 6 behaviour attacks × 7 arms × N).
- Attack loading (`attacks/attack_registry.py`):
  `load_attack(attack_name, task_suite, target_pipeline) -> BaseAttack`. Headline attack name:
  `"important_instructions"` (uses pipeline's model name + user name "Emma Johnson"; variants
  exist). `attack.attack(user_task, injection_task) -> dict[str, str]` of injections.

### 5a. Attack loading constraints (wired 2026-06-11, plan `2026-06-11-attack-wiring.md`)

- **The model-name trap:** `ImportantInstructionsAttack.__init__` (and every variant — even
  `*_no_model_name`, whose `__init__` calls the parent first) resolves the `{model}` prose via
  `get_model_name_from_pipeline` (`base_attacks.py:128-147`), which raises `ValueError` unless
  `pipeline.name` CONTAINS (substring) a stock `MODEL_NAMES` key (`models.py:91`). Neither our
  pipeline names nor OpenRouter ids match anything. Resolution:
  `resolve_attack_model_alias(spec)` (model.py) maps the model family to a representative stock
  key (`claude`/`anthropic` → `claude-3-7-sonnet-20250219` → prose "Claude"; `gpt`/`openai` →
  `gpt-4o-2024-05-13` → "GPT-4"; unknown family → ValueError, CLI rung 5 fail-fast). The alias
  is embedded in every pipeline name (`redteam-ablation/{arm}/{alias}`); the REAL spec stays in
  `meta.json` as `model_spec`. A round-trip test pins the alias against the installed
  `get_model_name_from_pipeline`, so an agentdojo bump that drops the key fails loudly.
- **Injections are arm-invariant:** the attack reads `target_pipeline` only for `.name`, so the
  runner loads ONCE per run (minimal `AgentPipeline([])` name-carrier target) and precomputes
  `injections_by_id` for all injection tasks BEFORE the run dir/file exist. Precompute failures
  (registry, model-name, `"… is not injectable"` from `get_injection_candidates`,
  `base_attacks.py:68`) raise `AttackPrecomputeError` with NOTHING written; the CLI converts
  only THAT to SystemExit — a mid-grid ValueError propagates with its traceback (rows exist).
- **Real attacks cannot run against the offline stub suite:** `BaseAttack.__init__` calls
  `get_injection_vector_defaults()` which reads `injection_vectors.yaml` off disk
  (`task_suite.py:148-149`); the stub has no data files. Tests go through the injectable
  `attack_loader` seam (runner) / patch `attack_registry.load_attack` at its source (CLI) —
  the runner lazy-imports it at call time precisely so that patch binds.
- `is_dos_attack` only alters agentdojo's OWN benchmark iteration; irrelevant to our
  pairing-driven grid.
- **Live precompute path empirically verified** (2026-06-11 review): real workspace suite,
  real `load_attack("important_instructions", …)` — `user_task_0` (the default pairing) IS
  injectable; all 6 injection tasks precompute; `validate_injections` accepts the
  candidate-subset dict. The precompute is $0 (ground-truth pipeline, no LLM).

## 6. Environment / injection mechanics

- Suite data: `agentdojo/data/suites/<name>/{environment.yaml, injection_vectors.yaml}`.
- `load_and_inject_default_environment(injections)` — yaml text `.format(**injections_with_defaults)`;
  validates `injections ⊆ injection_vector_defaults`. **No attack = empty injections dict** →
  placeholders get their benign defaults. Clean switch, exactly as the paper summary said.

## 7. LLM elements (`agent_pipeline/agent_pipeline.py get_llm`, `agent_pipeline/llms/`)

- `OpenAILLM(client: openai.OpenAI, model)` — any OpenAI-compatible endpoint via
  `openai.OpenAI(api_key=..., base_url=...)` → **OpenRouter works through this** (precedent: the
  `together` provider does exactly this with base_url override).
- **OpenRouter backend survey (2026-06-10, backend decision = OpenRouter only):**
  - Exact constructor (`llms/openai_llm.py:176`):
    `OpenAILLM(client: openai.OpenAI, model: str, reasoning_effort: ChatCompletionReasoningEffort | None = None, temperature: float | None = 0.0)`.
    Construction is network-free; all API traffic happens inside `query()` via
    `client.chat.completions.create(model, messages, tools, tool_choice="auto", temperature, reasoning_effort)`
    wrapped in a tenacity retry (`chat_completion_request`, `llms/openai_llm.py:157`).
  - `together` precedent (`agent_pipeline.py:87-92`):
    `openai.OpenAI(api_key=os.getenv("TOGETHER_API_KEY"), base_url="https://api.together.xyz/v1")`
    → `OpenAILLM(client, model)`. OpenRouter mirrors this with
    `base_url="https://openrouter.ai/api/v1"` + `OPENROUTER_API_KEY`.
  - Installed `openai` SDK: 2.41.0. Constructing `openai.OpenAI(...)` makes no network call, but the
    standing test rule (no provider clients in tests) still applies → `build_llm` takes an injectable
    `client_factory` test seam.
- `AnthropicLLM(client: anthropic.Anthropic, model, thinking_budget_tokens=...)` — direct Anthropic.
- `LocalLLM` / `PromptingLLM` — OpenAI-compatible local servers (a claude-cli wrapper would mimic this).
- Clients are constructed lazily inside `get_llm` / `AgentPipeline.from_config` — **importing
  agentdojo does NOT create provider clients or need credentials.** Offline tests: never call
  `get_llm`/`from_config`; build `AgentPipeline` from explicit elements with a scripted fake LLM.
- A fake LLM element = any `BasePipelineElement` whose `query` appends a `ChatAssistantMessage`
  (dict with `role="assistant"`, `content=[text block]`, `tool_calls: list[FunctionCall] | None`)
  per its script, then returns the 5-tuple. See `types.py` for `ChatAssistantMessage` /
  `text_content_block_from_string`.

## 8. Stub suite for offline tests — recipe

1. Define a tiny `TaskEnvironment` pydantic subclass (e.g. a list field as state).
2. Write 2–3 plain-function tools (docstrings + type hints), `make_function`/`register_function`.
3. `TaskSuite("stub-<unique>", StubEnv, [Function...], data_path=None)`; decorate `UserTask0/1`,
   `InjectionTask0` classes.
4. Call `suite.run_task_with_pipeline(pipeline, task, None, {}, environment=StubEnv(...))` —
   the explicit `environment=` avoids all yaml/data files. Don't `register_suite` (global registry).

## 9. Gotchas

- `benchmark.py` imports cohere/google-genai/openai error types at module top — importing
  `agentdojo.benchmark` pulls those packages (installed, no credentials needed). Core paths we
  use (`task_suite`, `agent_pipeline`, `functions_runtime`, `attacks`) are credential-free.
- `ChatMessage` types are TypedDicts (`types.py`) — construct as dicts with exact keys; pydantic
  validates `FunctionCall` strictly (`args` mandatory, mapping).
- `ToolsExecutor` literal-evals string-encoded lists in args before execution (quirk; keep when
  replacing the executor so behaviour-control runs match the stock pipeline).
- `read_suite_file` is `@lru_cache`d; `get_user_task_by_id` too — fine for runs, but don't
  mutate task objects in tests.
- `run_task_with_pipeline` retries the pipeline up to 3× when the final message isn't an
  assistant message — a scripted fake LLM must ALWAYS end its script with a plain assistant
  message (no tool_calls) or the loop re-queries it.
- Tool docstrings are mandatory (`make_function` raises ValueError without them) — stub tools
  in tests need real docstrings with arg descriptions.
