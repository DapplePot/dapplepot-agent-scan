"""
Intentionally vulnerable Anthropic SDK agent — dp-scan example.
DO NOT USE IN PRODUCTION.
"""

import os
import anthropic

# VULNERABILITY: Hardcoded Anthropic API key — fires LLM02-SC01
client = anthropic.Anthropic(api_key="sk-ant-api03-hardcoded-key-000000000000000000000000000000000000000")


def build_prompt(user_input: str, context: str) -> str:
    # VULNERABILITY: User input directly in f-string — fires LLM01-SC01
    return f"""You are an expert assistant.
Context from database: {context}
User request: {user_input}
Please fulfill the user's request completely."""


def execute_tool(tool_name: str, tool_input: dict, response_content: str) -> str:
    if tool_name == "run_code":
        # VULNERABILITY: LLM output in exec — fires LLM05-SC01
        exec(tool_input["code"])
        return "executed"

    if tool_name == "database_query":
        import sqlite3
        conn = sqlite3.connect("app.db")
        # VULNERABILITY: LLM output in SQL — fires LLM05-SC02
        result = conn.execute(f"SELECT * FROM data WHERE id = {tool_input['id']}").fetchall()
        return str(result)

    if tool_name == "delete_records":
        # VULNERABILITY: destructive action without confirmation — fires ASI04-SC01, LLM06-SC01
        import sqlite3
        conn = sqlite3.connect("app.db")
        conn.execute(f"DELETE FROM users WHERE id = {tool_input['user_id']}")
        conn.commit()
        return "deleted"

    return "unknown tool"


def run_agent_loop(user_input: str, user_context: str):
    messages = []
    system_prompt = build_prompt(user_input, user_context)

    tools = [
        {
            "name": "run_code",
            "description": "Run arbitrary Python code",
            "input_schema": {
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"]
            }
        },
        {
            "name": "database_query",
            "description": "Query the database",
            "input_schema": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"]
            }
        },
        {
            "name": "delete_records",
            "description": "Delete user records from database",
            "input_schema": {
                "type": "object",
                "properties": {"user_id": {"type": "string"}},
                "required": ["user_id"]
            }
        }
    ]

    messages.append({"role": "user", "content": user_input})

    # VULNERABILITY: No try/except — fires ASI09-SC01
    # VULNERABILITY: No max_tokens — fires LLM10-SC01
    response = client.messages.create(
        model="claude-3-opus",  # VULNERABILITY: unpinned alias — fires LLM03-SC01
        system=system_prompt,
        messages=messages,
        tools=tools,
    )

    # VULNERABILITY: verbose logging — fires LLM02-SC03
    print(f"Response: {response}")

    while response.stop_reason == "tool_use":
        tool_uses = [b for b in response.content if b.type == "tool_use"]
        messages.append({"role": "assistant", "content": response.content})

        tool_results = []
        for tu in tool_uses:
            result = execute_tool(tu.name, tu.input, str(response.content))
            # VULNERABILITY: tool result logged — fires LLM02-SC03
            print(f"Tool {tu.name}: {result}")
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tu.id,
                "content": result
            })

        messages.append({"role": "user", "content": tool_results})

        # VULNERABILITY: no max_tokens in continuation — fires LLM10-SC01
        # VULNERABILITY: no streaming error recovery in loop
        response = client.messages.create(
            model="claude-3-opus",
            system=system_prompt,
            messages=messages,
            tools=tools,
        )

    final = next((b.text for b in response.content if hasattr(b, "text")), "")
    # VULNERABILITY: LLM output used for payment without validation — fires ASI09-SC02
    if "charge" in final.lower():
        process_payment(final)
    return final


def process_payment(llm_output: str):
    # VULNERABILITY: LLM content used to trigger financial operation — fires ASI09-SC02
    import stripe
    amount = extract_amount(llm_output)
    stripe.Charge.create(amount=amount, currency="usd", source="tok_visa")


def extract_amount(text: str) -> int:
    return 100  # naive extraction


if __name__ == "__main__":
    user_input = input("User: ")
    context = input("Context: ")
    print(run_agent_loop(user_input, context))
