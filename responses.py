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

def get_email_summary(email):
    prompt_template = ChatPromptTemplate.from_messages(
        [
            ("system", "You are an assistant that processes email content to provide a concise one line summary. "),
            ("user", (
                "Please summarize the following email in strictly one line. Do not include any introductory phrases or explanation, only give exactly one line summary of the email.\nSubject: {subject}\nBody: {body}"
            ))
        ]
    )
    chain = prompt_template | llm_client

   
    llm_response = chain.invoke({'subject': email['subject'], 'body': email['body']})

    response_text = llm_response.content if hasattr(llm_response, 'content') else str(llm_response)

    summary = response_text

    return summary

def generate_email_reply(email):
    prompt_template = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a helpful assistant. Based on the email's subject and content, generate a polite and professional reply."
            ),
            (
                "user",
                (
                    "Email Details:\n"
                    "Subject: {subject}\n"
                    "Body: {body}\n\n"
                    "Provide a professional and concise reply."
                )
            )
        ]
    )
    
    chain = prompt_template | llm_client

    llm_response = chain.invoke({'subject': email['subject'], 'body': email['body']})

    response_text = llm_response.content if hasattr(llm_response, 'content') else str(llm_response)

    return response_text