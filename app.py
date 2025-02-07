from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import requests
import base64

load_dotenv()

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")

# Initialize MongoDB
client = MongoClient(MONGO_URI)
db = client["url_scanner"]
reported_urls = db["reported_urls"]

# Define a Pydantic model for the request body
class ReportUrlRequest(BaseModel):
    url: str

# FastAPI instance
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Allow requests from the frontend
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Google Safe Browsing API URL
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

# Function to check URL in Google Safe Browsing
def check_google_safe_browsing(url):
    payload = {
        "client": {"clientId": "SafeLinkScanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(SAFE_BROWSING_URL, json=payload)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        return "dangerous" if "matches" in data else "safe"
    except requests.exceptions.RequestException as e:
        print(f"Google Safe Browsing API error: {e}")
        return "error"

# Function to check VirusTotal API
def check_virustotal(url):
    # Encode the URL in base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        result = response.json()
        if result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            return "dangerous"
        return "safe"
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal API error: {e}")
        return "error"

# Route to scan a URL
@app.get("/scan/")
def scan_url(url: str):
    # Check if already reported
    reported = reported_urls.find_one({"url": url})
    if reported:
        return {"url": url, "status": "dangerous", "source": "user reports"}

    # Check with Google Safe Browsing
    google_status = check_google_safe_browsing(url)
    if google_status == "error":
        return {"url": url, "status": "error", "source": "Google Safe Browsing"}
    
    # If Google flags it, return immediately
    if google_status == "dangerous":
        return {"url": url, "status": "dangerous", "source": "Google Safe Browsing"}
    
    # Check with VirusTotal
    vt_status = check_virustotal(url)
    if vt_status == "error":
        return {"url": url, "status": "error", "source": "VirusTotal"}

    # Return final result
    return {"url": url, "status": vt_status, "source": "VirusTotal" if vt_status == "dangerous" else "None"}

# Update the report_url function to accept JSON
@app.post("/report/")
def report_url(request: ReportUrlRequest):
    url = request.url  # Extract the URL from the request body
    if reported_urls.find_one({"url": url}):
        raise HTTPException(status_code=400, detail="URL already reported.")
    
    reported_urls.insert_one({"url": url})
    return {"message": "URL reported successfully", "url": url}