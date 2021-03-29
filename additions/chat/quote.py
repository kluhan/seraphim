import json
import random
import importlib


class Quote:
    def __init__(self):
        with importlib.resources.open_text('seraphim.resources','quotes.json') as quotes_file:
            self.quotes = json.load(quotes_file)["quotes"]

    def get(self):
        return random.choice(self.quotes)
