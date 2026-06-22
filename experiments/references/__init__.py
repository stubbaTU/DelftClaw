"""Hand-written reference implementations of the four fixed SQ3 specs.

Each module is a model-independent ground truth for one
``protocol/examples/*.md`` descriptor: the conformance oracle the SQ3 study
judges LLM compilations against (Step 1 of the redesign). A reference mirrors the
compiler's generated-class contract (``protocol/compiler.py``) closely enough to
(a) share an IPv8 community with any compiled overlay of the same descriptor and
(b) emit byte-identical wire frames, so a compiled overlay and its reference can
be run as two live nodes and compared on observable behaviour.

The reference is NOT compiled or sandboxed — it is ordinary Python, loaded
directly by ``sq3.oracle.reference_overlay``. Its handler bodies transcribe the
descriptor's ``### Handler`` prose verbatim; if the prose and the code disagree,
the prose wins and the code is the bug.
"""
