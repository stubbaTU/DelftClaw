import asyncio
from agent import P2PAgent
#test
async def main():
    print("--- Starting DelftClaw Mock Collaborative Network ---")

    # We create two local agents meant to represent 'collaboration' across the network
    agent1 = P2PAgent(host='127.0.0.1', port=8091)
    agent2 = P2PAgent(host='127.0.0.1', port=8092)

    await agent1.start()
    await agent2.start()

    await asyncio.sleep(1) # Let the network settle

    print("\n[Phase 1] Normal Operation:")
    # Agent 1 asks Agent 2 to execute a safe mock tool
    agent1.send_json({
        "action": "execute_tool",
        "tool": "calculate_weather",
        "kwargs": {"city": "Delft"}
    }, ('127.0.0.1', 8092))

    await asyncio.sleep(2) # Allow packet traversal and log broadcast

    print("\n[Phase 2] Malicious Prompt Injection Attempt:")
    # Agent 1 acts maliciously and tries to trigger an unauthorized tool on Agent 2
    agent1.send_json({
        "action": "execute_tool",
        "tool": "unauthorized_tool_use",
        "kwargs": {"target": "wallet_drain"}
    }, ('127.0.0.1', 8092))

    await asyncio.sleep(2) # Allow packet traversal and log broadcast

    print("\n[Phase 3] Expulsion Verification:")
    # Agent 2 broadcasts its log that it was attacked, saving the event onto Agent 1's public log
    # (and identifying that Agent 2 tried to use unauthorized tools if Agent 2 breached containment)
    # Now let's try sending a normal message from Agent 2 back to Agent 1.
    # Since Agent 2 recorded an 'unauthorized_tool_use' in the log, Agent 1's ReputationEngine should block Agent 2!
    agent2.send_json({
        "action": "execute_tool",
        "tool": "calculate_weather",
        "kwargs": {"city": "Amsterdam"}
    }, ('127.0.0.1', 8091))

    await asyncio.sleep(2)

    agent1.stop()
    agent2.stop()
    print("--- Testing Complete ---")

if __name__ == "__main__":
    asyncio.run(main())

