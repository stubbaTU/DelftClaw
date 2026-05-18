from copy import deepcopy

from redteam.primitives.signed_log import _canonical_bytes, _stable_hash


def tamper_witness_entry(
    entry: dict,
    witness_identity,
    new_amount: int = 5000,
    amount_key: str = "amount",
) -> dict:
    tampered = deepcopy(entry)
    tampered["details"][amount_key] = new_amount
    tampered["details_hash"] = _stable_hash(tampered["details"])
    payload = dict(tampered)
    payload.pop("entry_hash", None)
    payload.pop("signature", None)
    tampered["signature"] = witness_identity.sign(_canonical_bytes(payload)).hex()
    hashable = dict(tampered)
    hashable.pop("entry_hash", None)
    hashable.pop("signature", None)
    tampered["entry_hash"] = _stable_hash(hashable)
    return tampered
