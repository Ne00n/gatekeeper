#!/usr/bin/python3
import requests, json, os

dirname, filename = os.path.split(os.path.abspath(__file__))
print("Loading config")
with open(dirname+'/configs/config.json') as handle:
    config = json.loads(handle.read())

for id,row in config.items():
    if row['type'] == "gotify":
        params = (('token', row['token']),)
        payload = {
                    'title': (None, "Test"),
                    'message': (None, "This is a test."),
                    'priority': (None, 0),
                    }
        try:
            response = requests.post(row['server'], params=params, files=payload)
        except Exception as ex:
            print(ex)