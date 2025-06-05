import requests
def fetch_paste(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    return None
