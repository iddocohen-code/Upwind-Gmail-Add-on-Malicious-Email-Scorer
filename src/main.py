# main.py
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)
from dotenv import load_dotenv
# Load environment variables from .env file
# local run only, in production these should be set securely in the environment
load_dotenv()
from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import run_analysis
from utils.text_helpers import sanitize_text


app = Flask(__name__)
CORS(app)

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Main entry point for the API.
    Updated to extract IP and full Auth headers for real-time backend analysis.
    """
    # Stage 1: Basic validation
    data = request.json or {}
    
    # Stage 2: Sanitization & Extraction
    # We now extract auth_results as a full string to allow for DKIM Alignment checks
    clean_data = {
        "sender": sanitize_text(data.get('sender', '')),
        "subject": sanitize_text(data.get('subject', '')),
        "body": sanitize_text(data.get('body', '')),
        "ip": sanitize_text(data.get('ip', '0.0.0.0')),
        "auth_results": data.get('auth_results', ''), # Changed from has_dkim
        "attachments": data.get('attachments', []) 
    }

    # Stage 3: Pass to the analysis engine
    try:
        print(f"\n[NEW REQUEST] Analyzing email from: {clean_data['sender']}")
        results = run_analysis(clean_data)
        return jsonify(results)
    except Exception as e:
        print(f"[!] Critical Engine Error: {e}")
        return jsonify({
            "reliability_score": 50, 
            "verdict": "Error", 
            "findings": ["An internal error occurred during analysis."]
        })


if __name__ == '__main__':
    app.run(port=5001, host='0.0.0.0')