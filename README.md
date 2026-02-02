# MITRE Enriched Snyk Issues
This is a script that will get the Snyk Issues from your Group, run them through the MITRE database, and then enrich each of the items in the output to contain this data. This enrichment is only applied to Snyk Code issues to expand on the data available within the Snyk API. 

# Prerequisites
- Snyk API access
- Snyk API token
- Projects imported to Snyk with issues

# Usage
To get a local file with issues - Run the following:

```
python3 get_enriched_issues.py --token "YOUR_SNYK_TOKEN" --group-id "YOUR_SNYK_GROUP_ID" --output my_enriched_issues.json
```

To get JSON output directly to pipe into another process:

```
python3 get_enriched_issues.py --token "YOUR_SNYK_TOKEN" --group-id "YOUR_SNYK_GROUP_ID"
```
