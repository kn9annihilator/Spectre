import json
import requests
import os
import re

# This constructs the path to the signatures file relative to this script
# This makes sure it works no matter where you run the main script from
DATA_FILE_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'waf_signatures.json')

def detect_waf(target_url):
    """
    Detects the presence of a WAF by sending probes and matching signatures.
    
    Args:
        target_url (str): The target URL to probe.
        
    Returns:
        str: The name of the detected WAF, or None if no WAF is detected.
    """
    # Ensure the URL has a scheme (http:// or https://)
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    try:
        # Load WAF signatures from the JSON file
        with open(DATA_FILE_PATH, 'r') as f:
            signatures = json.load(f)

        # Send a benign request first
        benign_res = requests.get(target_url, timeout=10, headers={'User-Agent': 'Spectre/1.0'})

        # Send a malicious-looking request to try and trigger the WAF
        malicious_url = f"{target_url}/?id=<script>alert(1)</script>"
        malicious_res = requests.get(malicious_url, timeout=10, headers={'User-Agent': 'Spectre/1.0'})

        # Check all signatures against both responses
        for waf in signatures:
            for res in [benign_res, malicious_res]:
                if waf['check_type'] == 'header':
                    header_value = res.headers.get(waf['pattern'])
                    if header_value and re.search(waf['value_regex'], header_value, re.IGNORECASE):
                        return waf['name']
                
                elif waf['check_type'] == 'body_regex':
                    if re.search(waf['pattern'], res.text, re.IGNORECASE):
                        return waf['name']

                elif waf['check_type'] == 'cookie':
                    # Iterate through all cookies in the response
                    for cookie_name in res.cookies.keys():
                        if re.search(waf['pattern'], cookie_name, re.IGNORECASE):
                            return waf['name']

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {target_url}: {e}")
        return None
    except FileNotFoundError:
        print(f"Error: Could not find the WAF signatures file at {DATA_FILE_PATH}")
        return None
        
    return None # No WAF was detected