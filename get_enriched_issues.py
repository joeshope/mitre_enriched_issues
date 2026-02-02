import requests
import argparse
import json
import sys
import os

# Configuration
SNYK_API_BASE_URL = "https://api.snyk.io/rest"
SNYK_API_VERSION = "2025-11-05" 
MITRE_API_BASE_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness"
CACHE_FILE_NAME = "mitre_cache.json"

def load_cache():
    """Loads the cache from disk if it exists."""
    if os.path.exists(CACHE_FILE_NAME):
        try:
            with open(CACHE_FILE_NAME, 'r') as f:
                print(f"[*] Loading MITRE cache from '{CACHE_FILE_NAME}'...")
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            print("[!] Cache file corrupted or unreadable. Starting with empty cache.")
            return {}
    return {}

def save_cache(cache_data):
    """Saves the current cache to disk."""
    try:
        with open(CACHE_FILE_NAME, 'w') as f:
            json.dump(cache_data, f, indent=4)
        print(f"[*] Cache successfully saved to '{CACHE_FILE_NAME}'")
    except IOError as e:
        print(f"[!] Warning: Could not save cache file: {e}")

def get_mitre_cwe_details(cwe_id, cache):
    """
    Fetches CWE details and extracts specific fields from the 'Weaknesses' list.
    """
    # 1. Check Cache immediately
    if cwe_id in cache:
        return cache[cwe_id]

    # 2. Fetch from API if not in cache
    url = f"{MITRE_API_BASE_URL}/{cwe_id}"
    print(f"       [*] Cache miss: Querying MITRE API for {cwe_id}...")
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            raw_data = response.json()
            
            # Locate the 'Weaknesses' list
            weaknesses_list = raw_data.get("Weaknesses", [])
            
            if isinstance(weaknesses_list, list) and len(weaknesses_list) > 0:
                target = weaknesses_list[0]
                
                # Extract and Map Fields
                filtered_data = {
                    "id": target.get("ID"),
                    "name": target.get("Name"),
                    "extendedDescription": target.get("ExtendedDescription"),
                    "PotentialMitigations": target.get("PotentialMitigations"),
                    "DemonstrativeExamples": target.get("DemonstrativeExamples")
                }

                # Update cache
                cache[cwe_id] = filtered_data
                return filtered_data
            else:
                print(f"       [!] Warning: 'Weaknesses' list empty or missing for {cwe_id}.")
                error_data = {"error": "No Weakness data found in response"}
                cache[cwe_id] = error_data
                return error_data

        elif response.status_code == 404:
            # Handle "CWE-123" vs "123" format differences
            if cwe_id.upper().startswith("CWE-"):
                numeric_id = cwe_id.split('-')[1]
                
                # Recursive call to get the data using the numeric ID
                result = get_mitre_cwe_details(numeric_id, cache)
                
                # CRITICAL FIX: 
                # Save the result (from the numeric lookup) to the ORIGINAL "CWE-XXX" key.
                # This prevents hitting the API and getting a 404 again for this key.
                cache[cwe_id] = result
                return result
            
            print(f"       [!] Warning: MITRE ID {cwe_id} not found (404).")
            error_data = {"error": "Not Found", "status": 404}
            cache[cwe_id] = error_data 
            return error_data
        else:
            print(f"       [!] Error fetching MITRE data: {response.status_code}")
            return {"error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        print(f"       [!] Exception querying MITRE: {e}")
        return {"error": str(e)}

def enrich_issues(issues, cache):
    """
    Iterates through issues and enriches 'code' type items using the cache.
    """
    print(f"\n[*] Starting enrichment for {len(issues)} issues...")
    enrichment_count = 0

    for issue in issues:
        attributes = issue.get("attributes", {})
        issue_type = attributes.get("type")

        if issue_type == "code":
            classes = attributes.get("classes", [])
            cwe_id = None
            
            # Extract CWE ID
            if isinstance(classes, list) and len(classes) > 0:
                for cls in classes:
                    cls_id = cls.get("id")
                    if cls_id:
                        cwe_id = cls_id
                        break
            elif isinstance(classes, dict):
                 cwe_id = classes.get("id")

            if cwe_id:
                # Pass the cache to the getter
                mitre_data = get_mitre_cwe_details(cwe_id, cache)
                
                if "attributes" not in issue:
                    issue["attributes"] = {}
                
                issue["attributes"]["mitre_enrichment"] = mitre_data
                enrichment_count += 1
            else:
                issue["attributes"]["mitre_enrichment"] = {"error": "No Class ID found in Snyk response"}

    print(f"[*] Enrichment complete. Enriched {enrichment_count} 'code' issues.")
    return issues

def get_group_issues(token, group_id):
    """
    Fetches all issues for a given Group ID using Snyk REST API.
    """
    url = f"{SNYK_API_BASE_URL}/groups/{group_id}/issues"
    headers = {"Authorization": f"token {token}", "Content-Type": "application/vnd.api+json"}
    params = {"version": SNYK_API_VERSION, "limit": 100}
    all_issues = []
    
    print(f"[*] Fetching issues for Group ID: {group_id}...")
    
    while url:
        try:
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code != 200:
                print(f"Error: {response.status_code} - {response.text}")
                sys.exit(1)

            data = response.json()
            if 'data' in data:
                all_issues.extend(data['data'])
                print(f"    - Retrieved {len(data['data'])} issues (Total: {len(all_issues)})")
            
            if 'links' in data and 'next' in data['links']:
                url = "https://api.snyk.io" + data['links']['next']
                params = {} 
            else:
                url = None
                
        except Exception as e:
            print(f"An error occurred: {e}")
            sys.exit(1)

    return all_issues

def main():
    parser = argparse.ArgumentParser(description="Fetch and Enrich Snyk Group Issues with Caching")
    parser.add_argument("--token", required=True, help="Your Snyk API Token")
    parser.add_argument("--group-id", required=True, help="The Snyk Group ID")
    parser.add_argument("--output", "-o", help="File path to save JSON output (optional)")
    args = parser.parse_args()

    # 1. Load Cache (Persistent)
    cwe_cache = load_cache()

    # 2. Get Snyk Data
    issues = get_group_issues(args.token, args.group_id)

    # 3. Enrich Data (Passing cache)
    enriched_issues = enrich_issues(issues, cwe_cache)

    # 4. Save Cache (Update persistent storage)
    save_cache(cwe_cache)

    # 5. Output
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(enriched_issues, f, indent=4)
            print(f"\n[+] Successfully saved {len(enriched_issues)} enriched issues to '{args.output}'")
        except IOError as e:
            print(f"Error writing to file: {e}")
    else:
        print(json.dumps(enriched_issues, indent=4))

if __name__ == "__main__":
    main()