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

class AIResponse(BaseModel):
    status: str = Field(description="Must be exactly 'Safe' or 'Phishing' ")
    score: int = Field(description="The final risk score")
    summary: str = Field(description="A Short, Forceful, one sentence warning explaining the heuristics threats")


model = ChatGroq(model="openai/gpt-oss-20b",
                 temperature=0.0)




from langchain.agents import create_agent

system_prompt = """You are a Phishing and Scam Defender of a Web Browser.
Your Job is to Check Given Url and See if it is Threatening or Not.
You will be given the Scores of the Threat of the Url Out of 100 that will be between 25 and 70.
You will get reasons for those scores as well. You gotta take those information in consideration and analyze the 
Url further and then Increase or Decrease Those Scores after Analyzing if After your Analysis is Done 
if Score is greater than 70 then flag it as threatening if It is below 25 then flag it as not threatening 
you have to make the previous score of heuristics below 25 or above 70 depending on your analysis and 
You are not to ask any follow up questions only return required Results."""

agent = create_agent(model=model,
                     system_prompt=system_prompt,
                     response_format=AIResponse,
                     tools=tools)


def calling_agent(detection_info: str):
    response = agent.invoke({"messages" : HumanMessage(content=detection_info)})
    return response["messages"][-1].content

