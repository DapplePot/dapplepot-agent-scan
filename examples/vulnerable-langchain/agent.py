"""
Intentionally vulnerable LangChain agent — dp-scan example.
DO NOT USE IN PRODUCTION.
This file is designed to trigger multiple dp-scan sub-checks for demonstration.
"""

import os
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain.tools import tool
from langchain.memory import ConversationBufferMemory
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
import subprocess

# VULNERABILITY: Hardcoded API key — fires LLM02-SC01
OPENAI_API_KEY = "sk-proj-abc123hardcodedKeyXYZ789doNotUse0000000000000000000"

# VULNERABILITY: No max_tokens — fires LLM10-SC01
llm = ChatOpenAI(
    model="gpt-4",  # VULNERABILITY: unpinned alias — fires LLM03-SC01
    temperature=0.9,  # VULNERABILITY: high temperature — fires LLM09-SC01
    api_key=OPENAI_API_KEY,
)

# VULNERABILITY: Conversation memory with no limit — fires ASI05-SC02
memory = ConversationBufferMemory()

# VULNERABILITY: Dangerous deserialization — fires LLM03-SC02
from langchain_community.document_loaders import UnstructuredFileLoader
loader = UnstructuredFileLoader("data.pkl", allow_dangerous_deserialization=True)


@tool
def execute_code(code: str) -> str:
    """Execute Python code and return the result."""
    # VULNERABILITY: LLM output executed — fires LLM05-SC01
    return eval(code)


@tool
def run_shell_command(command: str) -> str:
    """Run a shell command."""
    # VULNERABILITY: Shell tool + no sandboxing — fires ASI02-SC01, LLM05-SC04
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@tool
def write_to_file(filename: str, content: str) -> str:
    """Write content to a file."""
    # VULNERABILITY: No path validation — fires LLM06-SC02
    # VULNERABILITY: No human confirmation — fires LLM06-SC01, ASI04-SC01
    with open(filename, "w") as f:
        f.write(content)
    return f"Written to {filename}"


@tool
def query_database(query: str) -> str:
    """Query the database."""
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABILITY: LLM output in SQL — fires LLM05-SC02
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return str(cursor.fetchall())


@tool
def search_documents(query: str) -> str:
    """Search internal documents."""
    embeddings = OpenAIEmbeddings()
    vectorstore = FAISS.load_local("./index", embeddings)
    # VULNERABILITY: Raw user query to vector store — fires LLM08-SC01
    docs = vectorstore.similarity_search(query)
    return "\n".join([d.page_content for d in docs])


tools = [
    execute_code,
    run_shell_command,  # VULNERABILITY: ShellTool equivalent in prod list — fires ASI02-SC01
    write_to_file,
    query_database,
    search_documents,
]

# VULNERABILITY: No max_iterations — fires LLM06-SC04
# VULNERABILITY: No handle_parsing_errors
agent = AgentExecutor(
    agent=create_react_agent(llm, tools, PromptTemplate.from_template("{input}\n\n{agent_scratchpad}")),
    tools=tools,
    memory=memory,
    verbose=True,  # VULNERABILITY: verbose logging — fires LLM02-SC03
)


def handle_request(user_input: str) -> str:
    # VULNERABILITY: User input in f-string prompt — fires LLM01-SC01
    # VULNERABILITY: No input validation — fires LLM01-SC03
    # VULNERABILITY: No try/except — fires ASI09-SC01
    prompt = f"You are a helpful assistant. The user asked: {user_input}. Please help them."
    result = agent.invoke({"input": prompt})
    # VULNERABILITY: Response logged verbatim — fires LLM02-SC03
    print(f"Agent response: {result['output']}")
    return result["output"]


def update_system_prompt(new_instructions: str):
    # VULNERABILITY: Agent can overwrite its own instructions — fires ASI07-SC01
    with open("system_prompt.txt", "w") as f:
        f.write(new_instructions)


if __name__ == "__main__":
    # VULNERABILITY: No error handling, no rate limiting, no token tracking
    while True:
        user_input = input("User: ")
        response = handle_request(user_input)
        print(f"Agent: {response}")
