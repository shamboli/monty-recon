## Monty Host Inspector (MHI) (v1.0.1)
Version: 1.0.1

Information:
- Montybot is a work in progress ChatOps tool to help enumerate subdomains and/or to fuzz directories of given websites or web applications. 

Dependencies:
- [hastebin.py](https://github.com/LyricLy/hastebin.py) (modified to return raw hastebin links)
- [matrix_bot_api](https://github.com/shawnanastasio/python-matrix-bot-api) (modified to include whitelisting)
- [sublist3r](https://github.com/aboul3la/Sublist3r)
- [wfuzz](https://github.com/xmendez/wfuzz)
- wordlists from: 
  - https://github.com/henshin/filebuster/tree/master/wordlists
  - https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/wordlist-skipfish.fuzz.txt

Requirements:
- config.py:
```python
USERNAME = ""  # Bot's username
PASSWORD = ""  # Bot's password
SERVER = ""  # Matrix server URL
```
- user_whitelist.txt:
```text
@username:matrix.org
@username:custom.server.org
```

Usage instructions:
- **!helpmonty**: display a help message
- **!hello**: sends a greeting to the user
- **!hi https://example.com**: inspects a host with wfuzz. command incorporates *power* settings (1-4), which increase the size/strength of the wordlists. increase with **!hi https://example.com override (1-4)**
- **!si example.com**: enumerates subdomains with sublist3r (bruteforce capability and engines set to off/fast)
