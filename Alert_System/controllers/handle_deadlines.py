from langchain_groq import ChatGroq
import os
import datetime
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv
load_dotenv() # take/load environment variables from .env.

os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_API_KEY"] = os.getenv("LANGCHAIN_API_KEY")
groq_api_key = os.getenv("GROQ_API_KEY")


llm_client = ChatGroq(api_key=groq_api_key,model_name="llama3-8b-8192")


            
def fetch_deadline(email):
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    
     # Create a ChatPromptTemplate to manage the prompt structure
    prompt_template = ChatPromptTemplate.from_messages(
        [
            ("system", "You are a helpful AI email alert and automation bot.Today is {date}. Your specialty is {specialty}."),
            ("user", (
                "For the email below, respond with any deadlines in this format:\n"
                "- Date: DD-MM-YYYY\n"
                "- Task: Brief task description as an alert user can understand it\n"
                "- Urgency: High/Medium/Low (if applicable)\n\n"
                "Subject: {subject}\nBody: {body}"
            ))
        ]
    )
   

    chain = prompt_template | llm_client

    # Generate prompt by filling in the subject and body of each email
    llm_response = chain.invoke({'specialty': 'for the email you are processing, check for deadlines and format it based on user requirements.If you think the email does not contain deadlines, respond with None.', 'subject': email['subject'], 'body': email['body'], 'date': date})
    

    #to get 
    response_text = llm_response.content if hasattr(llm_response, 'content') else str(llm_response)

    return response_text    






