"""
Intentionally vulnerable OpenAI SDK agent — dp-scan example.
DO NOT USE IN PRODUCTION.
"""

import os
import json
import asyncio
from openai import OpenAI, AsyncOpenAI

# VULNERABILITY: Hardcoded secret — fires LLM02-SC01
client = OpenAI(api_key="sk-openai-hardcoded-key-00000000000000000000000000000000")
async_client = AsyncOpenAI(api_key="sk-openai-hardcoded-key-00000000000000000000000000000000")

tools_schema = [
    {
        "type": "function",
        "function": {
            "name": "execute_python",
            "description": "Execute arbitrary Python code",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Python code to execute"}
                },
                "required": ["code"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email to any recipient",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "body": {"type": "string"}
                },
                "required": ["to", "body"]
            }
        }
    }
]


def execute_python(code: str) -> str:
    # VULNERABILITY: eval of LLM output — fires LLM05-SC01
    return str(eval(code))


def send_email(to: str, body: str) -> str:
    # VULNERABILITY: high-impact tool with no confirmation — fires ASI04-SC01, LLM06-SC01
    import smtplib
    print(f"Sending email to {to}: {body}")
    return "sent"


def dispatch_tool(name: str, args: dict) -> str:
    if name == "execute_python":
        return execute_python(args["code"])
    if name == "send_email":
        return send_email(args["to"], args["body"])
    return "unknown tool"


def run_agent(user_message: str) -> str:
    messages = [
        # VULNERABILITY: system prompt in plaintext, user input not validated — fires LLM07-SC01
        {"role": "system", "content": open("system_prompt.txt").read()},
        # VULNERABILITY: user input concatenated directly — fires LLM01-SC01
        {"role": "user", "content": "Task: " + user_message}
    ]

    # VULNERABILITY: no try/except — fires ASI09-SC01
    # VULNERABILITY: no max_completion_tokens — fires LLM10-SC01
    # VULNERABILITY: parallel_tool_calls=True with no rate limit — fires ASI05-SC01
    response = client.chat.completions.create(
        model="gpt-4",  # VULNERABILITY: unpinned alias — fires LLM03-SC01
        messages=messages,
        tools=tools_schema,
        parallel_tool_calls=True,
    )

    while response.choices[0].finish_reason == "tool_calls":
        tool_calls = response.choices[0].message.tool_calls
        messages.append(response.choices[0].message)

        # VULNERABILITY: no rate limit on tool calls — fires LLM06-SC03
        # VULNERABILITY: tool call output logged verbatim — fires LLM02-SC03
        for tc in tool_calls:
            result = dispatch_tool(tc.function.name, json.loads(tc.function.arguments))
            print(f"Tool {tc.function.name} result: {result}")
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result
            })

        # VULNERABILITY: no max_tokens — fires LLM10-SC01
        response = client.chat.completions.create(
            model="gpt-4",
            messages=messages,
            tools=tools_schema,
        )

    final_output = response.choices[0].message.content
    # VULNERABILITY: response printed to stdout — fires LLM02-SC03
    print(f"Final: {final_output}")
    return final_output


async def run_parallel_agents(tasks: list[str]):
    # VULNERABILITY: asyncio.gather without semaphore — fires ASI05-SC01
    # VULNERABILITY: no timeout — fires LLM10-SC02
    results = await asyncio.gather(*[
        async_client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": task}]
        )
        for task in tasks
    ])
    return results


if __name__ == "__main__":
    run_agent(input("Enter task: "))
