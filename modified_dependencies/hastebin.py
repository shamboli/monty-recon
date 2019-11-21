import requests

def post(content):
    post = requests.post("https://hastebin.com/documents", data=content)
    return "https://hastebin.com/raw/" + post.json()["key"]