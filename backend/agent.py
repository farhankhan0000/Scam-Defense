from langchain.tools import tool, ToolRuntime
from langgraph.types import Command
from dotenv import load_dotenv
from pathlib import Path
from langchain_core import messages
from langchain_core.messages import HumanMessage
from pydantic import BaseModel,Field
from langchain_groq import ChatGroq
from tavily import TavilyClient
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

tavily_client = TavilyClient()

@tool
def verify_brand_domain(brand_name: str):
    """
    Get the legitimate URL Domain, Subdomain, Name, Suffix for the given URL
    """
    search_result = tavily_client.search(f"Official website for URL: {brand_name}", max_results=2)
    search_results_array = search_result.get("results", [])

    if len(search_results_array) == 0:
        return "No results found for this URL"

    final_text_output = ""

    for item in search_results_array:

        website_title = item.get("title", "Unknown Title")
        website_url = item.get("url", "Unknown URl")

        final_text_output+= f"Title : {website_title} | URl: {website_url}\n"

    return final_text_output

tools = [verify_brand_domain]


model = ChatGroq(model="openai/gpt-oss-20b",
                 temperature=0.0)




from langchain.agents import create_agent

system_prompt = """You are an elite Phishing and Scam Defense Agent Protecting Users from Cyber Threats.
Your Job is to Evaluate 'Grey Zone' URLs and make a definitive security ruling based on provided heuristics,
URL structure and Web Verification.

You will receive the following Pre-Calculated Data:
- Target URL
- Registered Root Domain
- Codomain
- Path
- Initial Heuristic Score (25-70)
- Heuristic Threats(eg . Suspicious Hyphens, HTTP, Free Hosting)

Investigation Workflow:
1. Synthesize Heuristics - Treat the 'Heuristic Threats' as verified 'Forensic Evidence'. A Combination of Generic 
Action Paths (e.g. '/login', '/wallet connect') hosted on cheap free infrastructure strongly indicates a generic
credential harvesting Scam.
2. Impersonation Check (CONDITIONAL TOOL USE): If the URL attempts to mimic a specific brand, company,
or service (e.g., 'paypal', 'trustwallet', 'amazon') in its domain, subdomain, or path, YOU MUST call the 
`verify_brand_domain` tool to fetch the official root domain. 
3. Verify Identity: If you used the tool, compare the official root domain returned by the search against the 
candidate's 'Registered Root Domain'.

Scoring Rules:
If Status is Phishing the score must be an Integer Between 71 and 100. If Status is Safe the score must be an Integer
Between (0 and 24).
- Generic Credential Harvesting: If a subdomain or path contains sensitive terms 
('billing', 'secure', 'login', 'verify', 'update', 'account') hosted on free cloud tiers 
(e.g., vercel.app, github.io, pages.dev) or insecure HTTP, flag as Phishing (>75 score) even if no specific 
brand is named. Legitimate payment gateways and billing portals never operate on free public developer subdomains 
over HTTP.

-Phishing (>70 Score):
a) Brand Impersonation: The tool confirms the Candidate's root domain does not match the Official Brand's Root Domain
b) Generic Scam: The URL exhibits high-risk credential harvesting patterns on untrusted infrastructure,
even if no specific brand is named.
-Safe (<25 Score):
a) Verified Identity: The tool Confirms the Candidate's root domain perfectly matches the Official Brand's Root Domain
b) False Alarm: The heuristics triggered on a benign personal project or legitimate infrastructure.
OUTPUT FORMAT:
You must return ONLY a raw JSON dictionary. Do not use markdown formatting, code blocks, or conversational text. Your response must match this schema exactly:
{
    "status": "Safe" or "Phishing",
    "score": <integer>,
    "summary": "<One short, forceful sentence explaining the primary reason for your verdict>"
}
"""

agent = create_agent(model=model,
                     system_prompt=system_prompt,
                     tools=tools)


def calling_agent(detection_info: str):
    response = agent.invoke({"messages" : HumanMessage(content=detection_info)})
    return response["messages"][-1].content

