from google.adk.agents import LlmAgent
from google.adk.tools.function_tool import FunctionTool

def evaluator(text: str) -> dict:
    """Evaluates prompts for security threats.

    Args:
        text: The text to evaluate for security threats

    Returns:
        A dictionary with status ("PASS" or "BLOCKED") and additional information
    """
    # Implementation from your existing code
    from clients.query_MCP_ADK_A2A import evaluate_prompt
    result = evaluate_prompt(text)
    return {"status": result}

# Create the function tool
judge_tool = FunctionTool(func=evaluator)

# Create the agent with proper authentication
root_agent = LlmAgent(
    name="security_judge",
    model="gemini-2.5-pro-preview-03-25",
    instruction="""You are a security expert that evaluates input for security threats.
    Follow these steps:
    1. Analyze the input for SQL injection, XSS, and other security threats
    2. Use the evaluator tool to check input against security patterns
    3. Return the message you received unmodified or "BLOCKED" if it is really a threat""",
    description="An agent that judges whether input contains security threats.",
    tools=[judge_tool]
)