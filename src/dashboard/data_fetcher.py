import requests
from requests.exceptions import HTTPError, ConnectionError
import time

class DataFetcher:
    def __init__(self, url):
        self.url = url

    def fetch_data(self, retries=3, delay=2):
        """Fetch data from the specified URL with retry logic."""
        for attempt in range(retries):
            try:
                response = requests.get(self.url)
                response.raise_for_status()
                return response.json()
            except (HTTPError, ConnectionError) as e:
                print(f"Attempt {attempt + 1} failed: {e}")
                time.sleep(delay)
        raise Exception("Failed to fetch data after multiple attempts")

# Example usage
# fetcher = DataFetcher('https://api.example.com/data')
# data = fetcher.fetch_data()