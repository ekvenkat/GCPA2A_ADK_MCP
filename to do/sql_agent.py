from google.adk.agents import LlmAgent
from google.adk.tools.function_tool import FunctionTool

def query_data(sql: str) -> str:
    """Execute SQL queries safely on the salaries database.

    Args:
        sql: SQL query to execute

    Returns:
        String representation of query results
    """
    # Import from server_mcp to avoid circular imports
    from servers.server_mcp import query_data as mcp_query_data
    return mcp_query_data(sql)

# Create the function tool
sql_tool = FunctionTool(func=query_data)

# Create the agent
sql_agent = LlmAgent(
    name="sql_assistant",
    model="gemini-2.5-pro-preview-03-25",
    instruction="""
        You are an expert SQL analyst working with a salary database.
        Follow these steps:
        1. For database columns, you can use these ones: work_year,experience_level,employment_type,job_title,salary,salary_currency,salary_in_usd,employee_residence,remote_ratio,company_location,company_size,fictitious_name and fictitious_surname
        2. Generate a valid SQL query, according to the message you received
        3. Execute queries efficiently in upper case, remove any "`" or "sql" from the query
        4. Return only the result of the query, with no additional comments
        Format the output as a readable text format.
        Finally, execute the query.
    """,
    description="An assistant that can analyze salary data using SQL queries.",
    tools=[sql_tool]
)