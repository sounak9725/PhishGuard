# SafeLinkScanner

SafeLinkScanner is a real-time URL scanning tool designed to identify and flag suspicious links. It helps users stay protected from malicious and phishing links by integrating APIs like Google Safe Browsing and VirusTotal. This project is available as a browser extension or mobile app with a simple interface and powerful backend.

## Features
- **Real-Time URL Scanning**: Detects potentially harmful URLs and provides immediate feedback.
- **Color-Coded Warnings**:
  - Green: Safe
  - Red: Dangerous
- **Report Phishing Links**: Allows users to report suspicious links for crowd-sourced data.
- **Integration with Google Safe Browsing and VirusTotal APIs**.

## Tech Stack
- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Python (FastAPI)
- **Database**: MongoDB (for storing user-reported URLs)

## How It Works
1. **URL Scanning**:
   - The system checks the provided URL against the Google Safe Browsing API and VirusTotal API.
   - It flags URLs as safe or dangerous based on API results and prior user reports.
2. **Reporting**:
   - Users can report suspicious URLs, which are saved in the database for future checks.
3. **Cross-Origin Support**:
   - Configured CORS middleware for smooth interaction between the frontend and backend.

## Installation
### Prerequisites
- Python 3.9 or higher
- MongoDB instance
- API keys for Google Safe Browsing and VirusTotal

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/SafeLinkScanner.git
   cd SafeLinkScanner
2. Install dependencies:
   ```bash
    pip install -r requirements.txt
