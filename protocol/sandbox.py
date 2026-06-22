"""AST whitelist and namespaced exec for LLM-generated overlay sources.

This is a *demo-grade* sandbox. The trust gradient is small because compiled
overlays only run after the peer has been admission-gated by the seedbox
donation, but the AST walk still rejects the obvious foot-guns (eval,
exec, open, subprocess, os.*, dunder attribute access, non-ipv8 imports).

For production-grade isolation, swap this for a subprocess+seccomp or
WASM sandbox without changing the public API: ``validate_ast(source)`` +
``safe_exec(source) -> namespace``.
"""

from __future__ import annotations

import ast


class SandboxError(Exception):
    """Raised when the generated source violates the whitelist."""


# Imports the generated overlay is allowed to make.
_ALLOWED_MODULES: frozenset[str] = frozenset({
    "ipv8.community",
    "ipv8.lazy_community",
    "ipv8.messaging.lazy_payload",
    "ipv8.peer",
    "ipv8.peerdiscovery.network",
    "msgpack",
    "struct",
    # Pure-compute hashing — no I/O, network, filesystem, or exec surface, so
    # it is as safe as struct/msgpack. Protocols that verify content hashes
    # (e.g. the donation-gated admission overlay's sha256/sha1 checks) cannot
    # be expressed without it.
    "hashlib",
    # Timestamps for protocols that stamp messages/state. No filesystem,
    # network, or exec surface; the only mild concern is time.sleep (handler
    # availability), which is outside the sandbox's escape-prevention threat
    # model and irrelevant to compile/interop measurement.
    "time",
})

# Builtin callables the generated source must NOT invoke.
_FORBIDDEN_BUILTINS: frozenset[str] = frozenset({
    "eval", "exec", "compile", "open", "__import__",
    "globals", "locals", "vars", "delattr", "setattr",
    "getattr",  # too easy to use to escape into dunders
    "input", "breakpoint",
})

# Attribute names the generated source must NOT access.
_FORBIDDEN_ATTRS: frozenset[str] = frozenset({
    "__class__", "__bases__", "__subclasses__", "__mro__",
    "__globals__", "__builtins__", "__dict__", "__init_subclass__",
    "__import__", "__loader__", "__spec__",
})


class _Walker(ast.NodeVisitor):
    """Single-pass validator. Raises ``SandboxError`` on first violation."""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name not in _ALLOWED_MODULES:
                raise SandboxError(f"forbidden import: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # ``from __future__ import ...`` is a compiler directive, not a real
        # module import — it cannot be used to escape the sandbox, and modern
        # LLM-generated code emits it routinely (``annotations`` especially).
        # Allow it explicitly so it doesn't count as a spurious compile failure.
        if node.module != "__future__" and node.module not in _ALLOWED_MODULES:
            raise SandboxError(f"forbidden import: from {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Block direct calls to forbidden builtins.
        if isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_BUILTINS:
            raise SandboxError(f"forbidden call: {node.func.id}(...)")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _FORBIDDEN_ATTRS:
            raise SandboxError(f"forbidden attribute access: .{node.attr}")
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        # Easiest blanket-ban — overlay code shouldn't be opening files /
        # spawning subprocess context managers anyway.
        raise SandboxError("'with' statements are not allowed in overlay code")

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        raise SandboxError("'async with' statements are not allowed in overlay code")

    def visit_Global(self, node: ast.Global) -> None:
        raise SandboxError("'global' is not allowed in overlay code")

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        raise SandboxError("'nonlocal' is not allowed in overlay code")


def validate_ast(source: str) -> None:
    """Raise ``SandboxError`` if ``source`` violates the overlay whitelist."""
    try:
        tree = ast.parse(source, mode="exec")
    except SyntaxError as exc:
        raise SandboxError(f"syntax error: {exc}") from exc
    _Walker().visit(tree)


# Names from ``builtins`` that the overlay sandbox is allowed to use.
# Hoisted to module scope so ``safe_exec`` does a per-call shallow copy
# instead of rebuilding the dict + scanning ``builtins.__dict__`` on
# every overlay compile.
_SAFE_BUILTIN_NAMES: tuple[str, ...] = (
    "abs", "all", "any", "bool", "bytes", "bytearray", "callable",
    "dict", "divmod", "enumerate", "filter", "float", "format",
    "frozenset", "hash", "hasattr",
    "hex", "int", "isinstance", "issubclass", "iter", "len", "list",
    "map", "max", "min", "next", "ord", "chr", "pow", "print",
    "range", "repr", "reversed", "round", "set", "slice", "sorted",
    "str", "sum", "tuple", "type", "zip",
    # ``hasattr`` is safe to expose even though ``getattr`` is forbidden:
    # ``getattr(x, '__class__')`` *returns* the dunder (an escape vector), but
    # ``hasattr`` only ever returns a bool — it cannot hand the generated code a
    # dangerous object, and the literal-dunder AST guard still blocks ``.__x__``.
    # ``divmod`` / ``format`` are pure value->value computation (no attribute or
    # object access); generated handlers reach for all three routinely, and a
    # missing builtin otherwise surfaces as a runtime NameError mid-exchange
    # rather than a clean compile result.
    "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
    "AttributeError", "RuntimeError", "NotImplementedError",
    "StopIteration", "True", "False", "None",
    "object", "super", "property", "staticmethod", "classmethod",
    "__build_class__",
    "__name__",
)

_BUILTINS_NS = __import__("builtins").__dict__
_SAFE_BUILTINS_TEMPLATE: dict = {
    name: _BUILTINS_NS[name]
    for name in _SAFE_BUILTIN_NAMES
    if name in _BUILTINS_NS
}


def _restricted_import(name: str, globals_=None, locals_=None, fromlist=(), level=0):
    """Module-scoped __import__ replacement used by ``safe_exec``."""
    import importlib
    # ``from __future__ import ...`` is a compiler directive (the AST walker
    # already permits it); ``__future__`` exposes only feature flags, no escape
    # vector, so allow the runtime import too.
    if name != "__future__" and name not in _ALLOWED_MODULES:
        raise SandboxError(f"runtime import blocked: {name}")
    return importlib.import_module(name)


def safe_exec(source: str) -> dict:
    """Validate then exec ``source`` in a fresh namespace; return the namespace.

    The namespace is seeded with a minimal builtin set so the generated
    code can do ordinary work (``len``, ``range``, ``isinstance``, …) but
    not call any of the forbidden primitives.
    """
    validate_ast(source)

    safe_builtins = dict(_SAFE_BUILTINS_TEMPLATE)
    safe_builtins["__import__"] = _restricted_import

    namespace: dict = {"__builtins__": safe_builtins, "__name__": "overlay_sandbox"}
    exec(compile(source, "<overlay>", "exec"), namespace)
    return namespace
