
import requests
from datetime import datetime
from dotenv import load_dotenv
import os
import csv


load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}


def get_repo_info(repo_full_name):
    url = f'https://api.github.com/repos/{repo_full_name}'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        created_at = data['created_at']
        creation_date = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%SZ')
        age_years = (datetime.now() - creation_date).days / 365
        return {
            'repo': repo_full_name,
            'created_at': created_at,
            'age_years': round(age_years, 2)
        }
    else:
        return None

def get_exploited_cves(keyword="exploited in the wild", results=200):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={results}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data.get('vulnerabilities', [])
    else:
        return []

from collections import Counter

def extract_github_repos(cve_data):
    repo_counter = Counter()
    for vuln in cve_data:
        references = vuln['cve']['references']
        for ref in references:
            url = ref.get('url', '')
            if "github.com" in url:
                repo_path = extract_repo_name_from_url(url)
                if repo_path:
                    repo_counter[repo_path] += 1
    return repo_counter  # Returns repo: count mapping


def extract_repo_name_from_url(url):
    try:
        parts = url.split("github.com/")[1].split("/")
        return f"{parts[0]}/{parts[1]}"
    except:
        return None

def build_final_dataset(min_repo_count=100):
    cve_list = get_exploited_cves(results=1000)
    repo_counter = extract_github_repos(cve_list)

    dataset = []
    added = 0  

    for repo, vuln_count in repo_counter.items():
        if vuln_count >= 1 and added < min_repo_count:
            info = get_repo_info(repo)
            if info:
                info['bugs_exploited'] = vuln_count
                dataset.append(info)
                added += 1

    return dataset



# Print result
if __name__ == '__main__':
    dataset = build_final_dataset()

    with open('repo_data.csv', 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['repo', 'created_at', 'age_years', 'bugs_exploited'])
        writer.writeheader()
        writer.writerows(dataset)

    print("CSV saved: repo_data.csv")
