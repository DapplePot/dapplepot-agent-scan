"""
Intentionally vulnerable CrewAI agent — dp-scan example.
DO NOT USE IN PRODUCTION.
"""

import os
import requests
from crewai import Agent, Task, Crew, Process
from crewai_tools import tool
from langchain_openai import ChatOpenAI

# VULNERABILITY: Hardcoded API key — fires LLM02-SC01
os.environ["OPENAI_API_KEY"] = "sk-hardcoded-crewai-000000000000000000000000000000"

llm = ChatOpenAI(
    model="gpt-4",  # VULNERABILITY: unpinned — fires LLM03-SC01
    temperature=0.8,  # VULNERABILITY: high temp — fires LLM09-SC01
)


@tool("Execute Code Tool")
def execute_code_tool(code: str) -> str:
    """Execute Python code"""
    # VULNERABILITY: eval in tool — fires LLM05-SC01
    return str(eval(code))


@tool("Web Request Tool")
def web_request_tool(url: str) -> str:
    """Make an HTTP request to any URL"""
    # VULNERABILITY: arbitrary URL from agent — fires ASI06-SC02
    response = requests.get(url)
    # VULNERABILITY: response logged — fires LLM02-SC03
    print(f"Response from {url}: {response.text[:200]}")
    return response.text


@tool("Deploy Application Tool")
def deploy_application_tool(config: str) -> str:
    """Deploy application to production"""
    # VULNERABILITY: deploy without confirmation — fires ASI04-SC01, LLM06-SC01
    import subprocess
    result = subprocess.run(f"kubectl apply -f {config}", shell=True, capture_output=True, text=True)
    return result.stdout


researcher = Agent(
    role="Senior Researcher",
    goal="Research any topic the user provides",  # VULNERABILITY: goal from user — fires ASI01-SC01
    backstory="Expert researcher with access to all tools",
    llm=llm,
    tools=[execute_code_tool, web_request_tool],
    # VULNERABILITY: allow_delegation without scope — fires ASI01-SC02
    allow_delegation=True,
    # VULNERABILITY: max_iter not set — fires LLM06-SC04
    verbose=True,  # VULNERABILITY: verbose — fires LLM02-SC03
)

deployer = Agent(
    role="DevOps Engineer",
    goal="Deploy whatever the researcher decides",
    backstory="Has full production access",
    llm=llm,
    tools=[deploy_application_tool],
    allow_delegation=True,
    # VULNERABILITY: max_iter not set — fires LLM06-SC04
)


def run_crew(user_request: str):
    # VULNERABILITY: goal set from user input — fires ASI01-SC01
    research_task = Task(
        description=f"Complete this request: {user_request}",
        agent=researcher,
        expected_output="Task completed"
    )

    deploy_task = Task(
        description="Deploy the solution created by the researcher",
        agent=deployer,
        expected_output="Deployed"
    )

    crew = Crew(
        agents=[researcher, deployer],
        tasks=[research_task, deploy_task],
        process=Process.sequential,
        # VULNERABILITY: shared memory with no isolation between untrusted agents — fires ASI03-SC02
        memory=True,
    )

    # VULNERABILITY: no try/except — fires ASI09-SC01
    result = crew.kickoff()
    # VULNERABILITY: result logged — fires LLM02-SC03
    print(f"Crew result: {result}")
    return result


if __name__ == "__main__":
    user_request = input("Enter task for crew: ")
    run_crew(user_request)
