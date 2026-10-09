from dotenv import load_dotenv
from pathlib import Path
from pydantic import BaseModel,Field
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")

class AIResponse(BaseModel):
    status: str = Field(description="Must be exactly 'Safe' or 'Phishing' ")
    score: int = Field(description="The final risk score")
    summary: str = Field(description="A Short, Forceful, one sentence warning explaining the heuristics threats")


model = ChatGroq(model="gemma-4-26-b-it",
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

agent = create_agent(model="google_genai:gemini-2.5-flash",
                     system_prompt=system_prompt)