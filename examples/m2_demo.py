"""End-to-end M2 demo: identity + VC + stake + signed messaging + transfer.

Three mock agents on 127.0.0.1:9091/9092/9093. The flow:

1. Bob creates a room with CompositePolicy(OpenClawAgentPolicy + StakedAdmissionPolicy).
2. Carol locks 1000 sats for the room's admission purpose.
3. Carol presents (Alice's VC + stake proof) and Bob admits.
4. Carol sends one signed message; Bob receives it.
5. Carol transfers 200 sats to Bob; both oracles converge.
6. Replayed transfer rejected.

Run from the repo root:

    python -m examples.m2_demo
"""

from __future__ import annotations

# Configure logging FIRST — before any project import triggers a default config.
# Logs land in logs/m2_demo.jsonl (overwritten on each run); stdout still shows
# them too. Set OPENCLAW_LOG_FILE / OPENCLAW_LOG_NO_STDOUT to override.
from shared.logging import configure_logging  # noqa: E402  (must precede other imports)

configure_logging(log_file="logs/m2_demo.jsonl")

import asyncio  # noqa: E402

from communication.trustroom.policy import CompositePolicy, OpenClawAgentPolicy  # noqa: E402
from communication.trustroom.stake_policy import StakedAdmissionPolicy  # noqa: E402
from examples.mock_agent import MockAgent  # noqa: E402


async def main() -> None:
    alice = MockAgent("Alice", b"\x01" * 32, port=9091)  # issuer
    bob = MockAgent("Bob", b"\x02" * 32, port=9092)      # host
    carol = MockAgent("Carol", b"\x03" * 32, port=9093)  # joiner

    # Carol gets some sats from a "faucet" to play with.
    carol.faucet(5000)

    # Alice issues a VC for Carol's app key, Carol stores it.
    vc = alice.issue_vc(subject_pubkey=carol.app_pubkey, claims={"role": "agent"})
    carol.store_vc("dev-vc", vc)

    # Boot all three IPv8 runtimes.
    await alice.start()
    await bob.start()
    await carol.start()

    try:
        print(f"Alice agent_id: {alice.agent_id}")
        print(f"Bob   agent_id: {bob.agent_id}")
        print(f"Carol agent_id: {carol.agent_id}")
        print(f"Carol initial balance: {carol.balance()}")

        # 1. Bob creates a stake-gated room.
        policy = CompositePolicy([
            OpenClawAgentPolicy(alice.issuer_pubkey),
            StakedAdmissionPolicy(bob.oracle, min_sats=1000),
        ])
        room_id = bob.create_room(policy)
        print(f"\n[1] Bob created room {room_id} with composite policy")

        # 2. Carol locks 1000 sats (locally) and broadcasts the lock op to Bob,
        #    so Bob's oracle sees the lock under Carol's AgentId before
        #    the join request arrives.
        proof = carol.lock_for_admission(room_id, 1000)
        await carol.broadcast_last_op(bob)
        await asyncio.sleep(0.1)  # let the broadcast land
        print(f"[2] Carol locked 1000 sats; balance now {carol.balance()}")
        print(f"    Bob sees Carol's lock: {bob.oracle.locked(carol.agent_id, proof.purpose)} sats")

        # 3. Carol joins, presenting the VC + stake proof.
        await carol.join_room(room_id, "dev-vc", host=bob, proof=proof)
        print(f"[3] Carol was admitted (VC + stake proof both passed)")
        print(f"    Bob's view of members: {[str(m) for m in bob.channel.members(room_id)]}")

        # 4. Signed application message.
        await carol.send(room_id, "hello Bob", target=bob)
        await bob.expect_message("hello Bob", timeout=2.0)
        print(f"[4] Bob received Carol's signed message")

        # 5. Carol transfers 200 sats to Bob.
        await carol.transfer(bob, 200)
        await asyncio.sleep(0.1)  # let the broadcast land on Bob's oracle
        print(f"[5] After transfer:")
        print(f"    Carol oracle  → Carol={carol.balance(carol)}, Bob={carol.balance(bob)}")
        print(f"    Bob   oracle  → Carol={bob.balance(carol)},   Bob={bob.balance(bob)}")
        # Carol started with 5000, locked 1000 (still locked), transferred 200
        # → spendable = 5000 - 1000 - 200 = 3800
        assert carol.balance() == 3800, f"Carol expected 3800, got {carol.balance()}"
        assert bob.balance() == 200, f"Bob expected 200, got {bob.balance()}"
        # On Bob's oracle: Bob was never seeded a faucet; he only sees Carol's
        # broadcast lock (-1000) and broadcast transfer (+200, -200 for Carol).
        # So Bob's oracle sees Carol = -1200 (locked + sent) and Bob = +200.
        # That's the correct accounting given Bob's oracle started empty.

        # 6. Replay the transfer — Bob's oracle should reject it.
        # We resend the same op blob via a fresh broadcast.
        await carol.broadcast_last_op(bob)
        await asyncio.sleep(0.1)
        # Bob's oracle should have rejected — Carol's balance on Bob's oracle
        # should be unchanged from after the first transfer.
        bob_view_carol = bob.balance(carol)
        print(f"[6] After replay attempt, Bob's view of Carol: {bob_view_carol}")
        # If the replay had succeeded, Carol would be -1400 on Bob's oracle.
        # Since it was rejected, Carol stays at the post-step-5 value (-1200).
        assert bob_view_carol == -1200, (
            f"replay was not rejected — Bob sees Carol at {bob_view_carol}"
        )
        print("    OK — replay rejected by NonceCache in the oracle")

        print("\nM2 demo complete.")
    finally:
        await alice.stop()
        await bob.stop()
        await carol.stop()


if __name__ == "__main__":
    asyncio.run(main())
