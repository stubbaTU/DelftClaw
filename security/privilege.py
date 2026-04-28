class Brain:
    """
    The reasoning core using the LLM.
    It plans what tools to execute but executes NONE of them.
    It has zero access to cryptographic keys or the environment.
    """
    def __init__(self, proxy):
        self.proxy = proxy

    def decide_action(self, context: dict) -> dict:
        # Example dummy LLM reasoning: decides to call a tool based on context
        decision = {
            "tool_name": "send_message",
            "tool_kwargs": {
                "recipient": "some_address",
                "message": "Hello!"
            }
        }
        self.proxy.log_action("llm_decision", decision)
        return decision

class Hands:
    """
    The secure tool execution layer.
    Holds the credentials (e.g. injected dynamically by host, or run natively out-of-sandbox)
    and executes tools authorized by the Brain.
    """
    def __init__(self, agent_reference):
        self.agent = agent_reference

    def execute(self, decision: dict):
        tool = decision.get("tool_name")
        kwargs = decision.get("tool_kwargs", {})

        # Privilege separation check before tool execution
        if tool == "send_message":
            # Allowed action, executing with privileges
            print("Executing authorized send_message tool.")
            # self.agent.send_json(kwargs.get("message"), kwargs.get("recipient_addr"))
            self.agent.proxy.log_action("tool_execution_success", decision)
        elif tool == "malicious_tool":
            print("Block: Attempted to call malicious tool.")
            self.agent.proxy.log_action("unauthorized_tool_use", decision)
        else:
            print(f"Tool {tool} not recognized.")

