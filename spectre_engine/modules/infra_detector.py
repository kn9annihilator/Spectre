import requests
import socket
import dns.resolver
from dns import exception # Import the exception module explicitly

# A dictionary of known headers that indicate a proxy or load balancer.
# The value is a short description of what the header typically means.
KNOWN_INFRA_HEADERS = {
    'via': 'Indicates the request was routed through a proxy.',
    'x-forwarded-for': 'Identifies the originating IP address of a client.',
    'x-real-ip': 'A common alternative to X-Forwarded-For.',
    'x-amz-request-id': 'Indicates use of an AWS Elastic Load Balancer.',
    'x-google-backend-id': 'Indicates use of a Google Cloud Load Balancer.',
    'x-azure-ref': 'Indicates use of Azure Front Door or other Azure services.',
    'server': 'Can reveal proxy software (e.g., nginx, awselb).',
    'cf-ray': 'Indicates the request was handled by Cloudflare.'
}

def detect_infrastructure(target):
    """
    Analyzes HTTP headers and DNS to infer infrastructure like proxies and load balancers.

    Args:
        target (str): The target domain to analyze.

    Returns:
        dict: A dictionary containing the analysis results.
    """
    findings = {
        "headers": [],
        "dns_load_balancing": {
            "detected": False,
            "ips": []
        }
    }
    
    url = f"https://{target}"

    # --- 1. HTTP Header Analysis ---
    try:
        res = requests.get(url, timeout=10, headers={'User-Agent': 'Spectre/1.0'})
        
        for header, value in res.headers.items():
            lower_header = header.lower()
            if lower_header in KNOWN_INFRA_HEADERS:
                if lower_header == 'server' and 'awselb' in value.lower():
                    description = "Indicates an AWS Elastic Load Balancer."
                else:
                    description = KNOWN_INFRA_HEADERS[lower_header]
                
                findings["headers"].append({
                    "header": header,
                    "value": value,
                    "description": description
                })

    except requests.exceptions.RequestException as e:
        print(f"Error during HTTP request: {e}")


    # --- 2. DNS-Based Load Balancing Check (Upgraded Logic) ---
    try:
        # Use dnspython to query for all 'A' records
        answers = dns.resolver.resolve(target, 'A')
        ips = [rdata.address for rdata in answers]
        
        findings["dns_load_balancing"]["ips"] = ips
        if len(ips) > 1:
            findings["dns_load_balancing"]["detected"] = True

    # --- THIS BLOCK IS CORRECTED ---
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, exception.Timeout) as e:
        print(f"Error during DNS resolution: {e}")

    return findings