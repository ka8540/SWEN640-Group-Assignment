import requests
from datetime import datetime
from dotenv import load_dotenv
import os
import csv
from collections import Counter

# Load token from .env
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

def get_exploited_cves(keyword="exploited in the wild", max_results=2000):
    all_vulns = []
    start_index = 0
    page_size = 200  # NVD API max per page

    while len(all_vulns) < max_results:
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={keyword}&resultsPerPage={page_size}&startIndex={start_index}"
        )
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            if not vulns:
                break  # no more data
            all_vulns.extend(vulns)
            start_index += page_size
        else:
            print(f"Request failed with status {response.status_code}")
            break

    return all_vulns[:max_results]


def extract_github_repos(cve_data):
    repo_counter = Counter()
    for vuln in cve_data:
        references = vuln['cve'].get('references', [])
        for ref in references:
            url = ref.get('url', '')
            if "github.com" in url:
                repo_path = extract_repo_name_from_url(url)
                if repo_path:
                    repo_counter[repo_path] += 1
    return repo_counter

def extract_repo_name_from_url(url):
    try:
        parts = url.split("github.com/")[1].split("/")
        owner = parts[0]
        repo = parts[1]
        return f"{owner}/{repo}"
    except:
        return None

def build_final_dataset(min_repo_count=400):
    cve_list = get_exploited_cves(max_results=5000)  # try fetching 5000 to filter more
    repo_counter = extract_github_repos(cve_list)

    dataset = []
    added = 0

    for repo, vuln_count in repo_counter.items():
        if added >= min_repo_count:
            break
        info = get_repo_info(repo)
        if info:
            info['bugs_exploited'] = vuln_count
            dataset.append(info)
            added += 1

    return dataset


if __name__ == '__main__':
    dataset = build_final_dataset()

    with open('repo_data.csv', 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['repo', 'created_at', 'age_years', 'bugs_exploited'])
        writer.writeheader()
        writer.writerows(dataset)

    print("CSV saved: repo_data.csv")
