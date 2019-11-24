import requests

def post(content):
    # Basic post for ghostbin 
    params = {}
    params['text'] = content
    url = 'https://ghostbin.co/paste/new'
    post = requests.post(url, params=params)
    
    return post.url