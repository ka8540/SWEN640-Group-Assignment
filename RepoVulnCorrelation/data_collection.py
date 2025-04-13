
import requests
from datetime import datetime
from dotenv import load_dotenv
import os


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

def get_exploited_cves(keyword="exploited in the wild", results=100):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage={results}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data.get('vulnerabilities', [])
    else:
        return []

def extract_github_repos(cve_data):
    matched_repos = []
    for vuln in cve_data:
        references = vuln['cve']['references']
        for ref in references:
            url = ref.get('url', '')
            if "github.com" in url:
                repo_path = extract_repo_name_from_url(url)
                if repo_path:
                    matched_repos.append(repo_path)
    return list(set(matched_repos))

def extract_repo_name_from_url(url):
    try:
        parts = url.split("github.com/")[1].split("/")
        return f"{parts[0]}/{parts[1]}"
    except:
        return None

def build_final_dataset(min_repo_count=20):
    cve_list = get_exploited_cves(results=200)
    repos = extract_github_repos(cve_list)
    
    dataset = []
    count = 0
    
    for repo in repos:
        if count >= min_repo_count:
            break
        info = get_repo_info(repo)
        if info:
            dataset.append(info)
            count += 1
    
    return dataset


# Print result
if __name__ == '__main__':
    for row in build_final_dataset():
        print(row)
