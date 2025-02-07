import os
import requests
from fastapi import FastAPI, HTTPException
from pymongo import MongoClient
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

load_dotenv()

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")

# initializing MongoDB
client = MongoClient(MONGO_URI)
db = client["url_scanner"]
reported_urls = db["reported_urls"]

# fastAPI instance
app = FastAPI()

# Serve static files (CSS)
app.mount("/static", StaticFiles(directory="static"), name="static")



# google Safe Browsing API URL
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

# functionGoogle Safe Browsing
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
    response = requests.post(SAFE_BROWSING_URL, json=payload)
    data = response.json()
    return "dangerous" if "matches" in data else "safe"


# function VirusTotal API okok
def check_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
    if response.status_code == 200:
        result = response.json()
        if result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            return "dangerous"
    return "safe"

# Routing this stuff to scan a URL
@app.get("/scan/")
def scan_url(url: str):
    # Check if already reported
    reported = reported_urls.find_one({"url": url})
    if reported:
        return {"url": url, "status": "dangerous", "source": "user reports"}

    # google safe browsing url checking
    google_status = check_google_safe_browsing(url)
    
    # ff Google flags it then return immediately
    if google_status == "dangerous":
        return {"url": url, "status": "dangerous", "source": "Google Safe Browsing"}
    
    # ckhecking with VirusTotal
    vt_status = check_virustotal(url)

    # return final result
    return {"url": url, "status": vt_status, "source": "VirusTotal" if vt_status == "dangerous" else "None"}

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("templates/index.html", "r") as file:
        return file.read()

# Define a Pydantic model for the request body
class ReportUrlRequest(BaseModel):
    url: str

# Update the report_url function to accept JSON
@app.post("/report/")
def report_url(request: ReportUrlRequest):
    url = request.url
    if reported_urls.find_one({"url": url}):
        raise HTTPException(status_code=400, detail="URL already reported.")
    
    reported_urls.insert_one({"url": url})
    return {"message": "URL reported successfully", "url": url}
