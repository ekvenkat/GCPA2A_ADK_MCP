from google.adk.agents import LlmAgent
from google.adk.tools.function_tool import FunctionTool

def mask_text(text: str) -> dict:
    """Masks sensitive data like PII in text using Google Cloud DLP.

    Args:
        text: The text to mask sensitive data in

    Returns:
        A dictionary with the masked text
    """
    # Implementation from your existing code
    from clients.query_MCP_ADK_A2A import mask_sensitive_data, PROJECT_ID
    masked_result = mask_sensitive_data(PROJECT_ID, text)
    return {"masked_text": masked_result}

# Create the function tool
mask_tool = FunctionTool(func=mask_text)

# Create the agent
mask_agent = LlmAgent(
    name="data_masker",
    model="gemini-2.5-pro-preview-03-25",
    instruction="""You are a privacy expert that masks sensitive data.
    Follow these steps:
    1. Identify PII and sensitive information in the text
    2. Use the mask_text tool to protect sensitive data
    3. Return the masked version of the input in plain text, in readable format""",
    description="An agent that masks sensitive data in text.",
    tools=[mask_tool]
)