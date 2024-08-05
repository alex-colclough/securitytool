import requests
import time
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Get API keys from environment variables
VT_API_KEY = os.getenv('vt_api_key')
URLSCAN_API_KEY = os.getenv('urlscan_api_key')

def check_virustotal(url):
    print("Checking with VirusTotal...")
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": VT_API_KEY, "resource": url}
    
    try:
        response = requests.get(api_url, params=params)
        result = response.json()
        
        if result["response_code"] == 1:
            positives = result["positives"]
            total = result["total"]
            return f"VirusTotal: {'Potentially malicious' if positives > 0 else 'Safe'}. {positives}/{total} security vendors flagged this URL."
        else:
            return "VirusTotal: URL not found in database."
    except requests.RequestException as e:
        return f"VirusTotal: An error occurred: {str(e)}"

def check_urlscan(url):
    print("Checking with urlscan.io...")
    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": URLSCAN_API_KEY}
    data = {"url": url}
    
    try:
        response = requests.post(api_url, headers=headers, json=data)
        result = response.json()
        
        if "result" in result:
            scan_id = result["uuid"]
            result_url = f"https://urlscan.io/result/{scan_id}/"
            
            # Wait for the scan to complete
            time.sleep(10)
            
            # Fetch the scan results
            result_response = requests.get(result_url + "api/")
            result_data = result_response.json()
            
            verdicts = result_data.get("verdicts", {})
            overall_score = verdicts.get("overall", {}).get("score", 0)
            
            return f"urlscan.io: Scan completed. Score: {overall_score}/100. Full results: {result_url}"
        else:
            return f"urlscan.io: {result.get('message', 'An error occurred')}"
    except requests.RequestException as e:
        return f"urlscan.io: An error occurred: {str(e)}"

def display_menu():
    print("\nMenu:")
    print("1. Check with VirusTotal")
    print("2. Check with urlscan.io")
    print("3. Check with Cisco Talos")
    print("4. Exit")

def main():
    url = input("Enter the URL you want to check: ")
    
    while True:
        display_menu()
        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            result = check_virustotal(url)
        elif choice == '2':
            result = check_urlscan(url)
        elif choice == '3':
            result = check_cisco_talos(url)
        elif choice == '4':
            print("Exiting...")
            break
        else:
            result = "Invalid choice. Please select 1-4."

        print("\nResult:")
        print(result)

if __name__ == "__main__":
    main()
