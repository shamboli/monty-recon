import requests
import json

def post(api_token, description, visibility, content):
    api_url = 'https://api.github.com/gists'
    token = 'token {}'.format(api_token)
    
    # Set the visibility to public if preferred, otherwise set to private
    if visibility.lower() == 'public':
        visibility = True
    elif visibility.lower() == 'private':
        visibility = False
    else:
        visibility = False
    
    headers = {'Authorization': token}
    params = {'scope': 'gist'}
    payload = {'description': description, 'public': visibility, 'files': {description: {'content': content}}}
    
    try:
        post = requests.post(api_url, headers=headers, data=json.dumps(payload))
        response = json.loads(post.text)
        return response['html_url']
    except Exception as e:
        return str(e)