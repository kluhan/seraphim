import json
import random

class Quote:

    def __init__(self):
        with open('quotes.json') as quotes_file:
            self.quotes = json.load(quotes_file)['quotes']

    def get(self):
        return random.choice(self.quotes)