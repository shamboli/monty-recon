import sys, os, re, random
import wfuzz
import socket
import config
import modified_dependencies.ghostbin as ghostbin

from Sublist3r.subbrute import subbrute
from Sublist3r import sublist3r
from matrix_bot_api.matrix_bot_api import MatrixBotAPI
from matrix_bot_api.mregex_handler import MRegexHandler
from matrix_bot_api.mcommand_handler import MCommandHandler

# Global variables
USERNAME = config.USERNAME
PASSWORD = config.PASSWORD
SERVER = config.SERVER

# main work 
def host_inspection(host, power):
    # light, fast, normal, thorough are power choices
    fuzzable_url = str(os.path.join(str(host), 'FUZZ'))
    power = int(power)
    print('trying to fuzz: {}'.format(fuzzable_url))
    if power == 1:
        filename = 'wl/light.txt'
    elif power == 2:
        filename = 'wl/fast.txt'
    elif power == 3:
        filename = 'wl/normal.txt'
    elif power == 4:
        filename = 'wl/thorough.txt'
    else: 
        error = 'Incorrect power provided.'
        return error
    
    host_data = []
    try:
        for r in wfuzz.fuzz(url=fuzzable_url, follow=True, hc=[404], payloads=[('file', dict(fn=filename))]):
            a = [r.code, r.url]
            host_data.append(a)
    except Exception as e:
        error = str(e)
        return error
    
    # Check to see if the results are somewhat valid by seeing if the first n results match the first n from the wordlist, otherwise return something else
    n = 0 
    sample_count = round(len(host_data)/5)
    host_samples = host_data[:sample_count]
    with open(filename) as file:
        challenge_lines = file.readlines()[0:sample_count]
    
    for i in range(0,sample_count-1):
        challenge = re.compile('/' + str(challenge_lines[i].strip('\n')) + '$')        
        
        for host in host_samples:
            if challenge.findall(host[1]):
                n += 1
    
    print('total matches: {}'.format(str(n)))
    print('total match percent: {}/{}'.format(n, sample_count))
    
    if n > sample_count/2: 
        # if more than half the results are trash we are assuming that it has a 404 redirect
        error = 'Match sample count failed check.'
        return error
    
    return host_data

def subdomain_inspection(host, room):
    # hardcoding engine power for now
    engine_power = 'light'
    
    # engine power: light, medium and very slow 
    if engine_power == str('light'):
        engine_list = 'google,yahoo,bing,ask,netcraft,virustotal,threatcrowd'
        bf = False
    elif engine_power == str('medium'):
        engine_list = 'google,yahoo,bing,ask,netcraft,dnsdumpster,virustotal,threatcrowd'
        bf = False
    elif engine_power == str('very_slow'):
        engine_list = 'google,yahoo,bing,ask,netcraft,dnsdumpster,virustotal,threatcrowd,baidu'
        bf = True
        # print that this is going to take forever
    else:  
        return False
    
    # enumerate subdomain information 
    try:
        domain_results = sublist3r.main(host, 200, None, ports=None, silent=True, verbose=False, enable_bruteforce=bf, engines=engine_list)
        print(domain_results)
        # return results
    except Exception as e:
        return str(e)
    
    port_results = []
    # try to do some basic port checking 
    room.send_html('Status:<br /><blockquote>Subdomain enumeration complete for {}. Port inspection initiated.</blockquote>'.format(host))
    print('- performing subdomain port inspection for host {}'.format(host))
    total_results = len(domain_results)
    current_iteration = 0
    percent_flag = 0
    for result in domain_results:
        port_result_holder = []
        # check 80 
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((result, 80))
            s.close()
            port_result_holder.append('80')
        except socket.error as e:
            print('Error connecting on port 80: {}'.format(str(e)))
            port_result_holder.append('0')
            
        # check 443
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((result, 443))
            s.close()
            port_result_holder.append('443')
        except socket.error as e:
            print('Error connecting on port 443: {}'.format(str(e)))
            port_result_holder.append('0')
        
        port_results.append(port_result_holder)
        
        current_percent = (current_iteration/total_results)*100
        rounded_percent = 5 * round(current_percent/5)
        if (int(rounded_percent) == 25) and (percent_flag == 0):
            room.send_html('<pre><code>{} percent complete: {}%.</pre></code>'.format(str(host), str(current_percent)))
            percent_flag += 1
        elif (int(rounded_percent) == 50) and (percent_flag == 1):
            room.send_html('<pre><code>{} percent complete {}%.</pre></code>'.format(str(host), str(current_percent)))
            percent_flag += 1
        elif (int(rounded_percent) == 75) and (percent_flag == 2):
            room.send_html('<pre><code>{} percent complete {}%.</pre></code>'.format(str(host), str(current_percent)))
            percent_flag += 1 
        
        print('Rounded {}, Current {}, % flag {}'.format(rounded_percent, current_percent, percent_flag))
        current_iteration += 1
    
    print('- subdomain port inspection completed for host {}'.format(host))
    # combine the lists
    results = {}
    results['domains'] = domain_results
    results['port_results'] = port_results
    
    return results
    
# callbacks
def help_callback(room, event):
    room.send_html("""
                    <h4 style="margin-bottom:0px">Monty Host Inspector (MHI)</h4>
                    <b>Version: 1.0.2</b><br />
                    <b>Information: </b><br />
                    <ul style="list-style=none">
                        <li>I can help you to enumerate subdomains and/or to fuzz directories of given websites or web applications.</li>
                        <li>It takes me time to return information! Please be patient.</li>
                    </ul>    
                    <b>Dependencies: </b><br />
                    <ul>
                        <li>ghostbin.py (requests wrapper for posting to ghostbin.co)</li>
                        <li>matrix_bot_api (modified to include whitelisting)</li>
                        <li>sublist3r</li>
                        <li>wfuzz</li>
                        <li>wordlists from: 
                            <ul>
                                <li>https://github.com/henshin/filebuster/tree/master/wordlists</li>
                                <li>https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/wordlist-skipfish.fuzz.txt</li>
                            </ul>
                        </li>
                    </ul>
                    <b>Usage instructions: </b><br />
                    <ul>
                        <li><b>!helpmonty</b>: this message</li>
                        <li><b>!hello</b>: sends a greeting to the user</li>
                        <li><b>!hi https://example.com</b> (defaults power to 1, increase with <b>!hi https://example.com override (1-4)</b></li>
                        <li><b>!si example.com</b>: enumerates subdomains with sublist3r (bf and engine power set to off/1)</li>
                    </ul>
                    """)
           
def hello_callback(room, event):
    # Somebody said hi, let's say Hi back
    room.send_html("<pre>Hello, " + event['sender'] + '</pre>')

def hi_callback(room, event):
    pattern = re.compile('^(https|http)\:\/\/(.*)')
    args = event['content']['body'].split()
    args.pop(0)

    if not (len(args) != 1 or len(args) != 3):
        # tell them some info
        room.send_html('too many or too few arguments for mon_ty to process. see <b>!helpmonty</b> for usage')
        return False
    else:
        if len(args) == 3:
            # make arguments readable
            hostname = args[0]
            override = args[1]
            power = args[2] 
            
            if override != 'override': 
                room.send_html('second argument is an override parameter. see <b>!helpmonty</b> for more info')
                return False
            
            if not isinstance(int(power), int):
                room.send_html('third argument must be an int ranging from 1-4. see <b>!helpmonty</b> for more info')
                return False
            
            if 1 < int(power) > 4:
                room.send_html('third argument must be between 1-4. see <b>!helpmonty</b> for more info')
                return False                
            
        elif len(args) == 1:
            hostname = args[0]
            power = 1
        
        if not pattern.findall(hostname): 
            room.send_text('improperly formatted url. please provide a url like http://google.com or https://google.com. Thank you.')
            return False
        
        else: 
            print('Inspecting {}.'.format(hostname))
            data = host_inspection(hostname, power)
            if isinstance(data, str):
                room.send_html('Error occurred during fuzzing. <pre><code>{}</code></pre>'.format(data))
            else: 
                joined_data = '<pre><code><b>Code: Returned record</b>'
                for item in data:
                    joined_data += '\n{} : {}'.format(item[0], item[1]) 
                try: 
                    room.send_html('{}\n</code></pre>'.format(joined_data))
                except:
                    data_post_url = ghostbin.post('\n'.join(data))
                    room.send_text('Request too large for Matrix to handle. View results at {}'.format(data_post_url))
                    
def si_callback(room, event):
    print(event)
    args = event['content']['body'].split()
    args.pop(0)
    
    if len(args) != 1:
        # tell them some info
        room.send_html('si command takes ONE, count it, one, argument. see <b>!helpmonty</b> for more info')
        return
    
    hostname = args[0]
    print('subdomain inspection callback initiated for {}'.format(hostname))
    # do error handling on this later 
    results = subdomain_inspection(hostname, room)
    
    if len(results['domains']) == 0:
        room.send_html('<pre>Domain formatted incorrectly</pre>')
        return
    if len(results) > 0: 
        # parse the results 
        i = 0
        formatted_results = []
        for domain in results['domains']:
            # join the domains with the ports
            webports = ''
            ports = results['port_results'][i]
            for port in ports:
                if port != '0':
                    # append the port
                    if len(webports) == 0:
                        webports = port
                    else: 
                        webports = webports + ' ' + port
            
            domain_result = str('Domain: {} || Webports: {}'.format(domain, webports))
            i += 1
            
            formatted_results.append(domain_result)
        
        # upload formatted_results to ghostbin and dump an error if fails
        try:
            print(formatted_results)
            data_post_url = ghostbin.post(str('\n'.join(formatted_results)))
            room.send_html('Results for <b>{}</b> (view @ {}):'.format(hostname, data_post_url))
        except Exception as e:
            room.send_html('Results for <b>{}</b> (data upload error):'.format(hostname))
            print('data upload error for domain {}'.format(hostname))
            print(str(e))
        
        try: 
            room.send_html('<pre><code>{}</code></pre>'.format('\n'.join(formatted_results)))
            print('subdomain inspection callback completed for {}'.format(hostname))
        except Exception as e:
            truncated_results = formatted_results[:150]
            room.send_text('Truncating to 150 results.')
            room.send_html('<pre><code>{}</code></pre>'.format('\n'.join(truncated_results)))
            print('subdomain inspection callback failed for {}'.format(hostname))
            print('reason: {}'.format(str(e)))
    
    return

def post_callback(room, event):
    fake_subdomain_event = {'event_id': 'abcdefg', 'sender': 'sender', 'origin_server_ts': 1234567890, 'content': {'msgtype': 'm.text', 'body': '!si matrix.org'}, 'room_id': '!abcdefg', 'unsigned': {'age': 99}, 'type': 'm.room.message'}
    fake_host_event = {'event_id': 'abcdefg', 'sender': 'sender', 'origin_server_ts': 1234567890, 'content': {'msgtype': 'm.text', 'body': '!hi https://matrix.org'}, 'room_id': '!abcdefg', 'unsigned': {'age': 99}, 'type': 'm.room.message'}
    room.send_html('<pre>Initiated callback POST with limited reporting.</pre>')
    
    room.send_html('<pre><code>Performing POST subdomain callback.</pre></code>')
    try: 
        si_callback(room, fake_subdomain_event)
    except Exception as e: 
        print('<pre><code>SI callback error: {}</code></pre>'.format(str(e)))
    
    room.send_html('<pre><code>Performing POST host inspection callback.</pre></code>')
    try: 
        hi_callback(room, fake_host_event)
    except Exception as e: 
        print('<pre><code>HI callback error: {}</code></pre>'.format(str(e)))
    
    room.send_html('<pre><code>Callback POST complete.</code></pre>') 
    return True
    

def main():
    # Create an instance of the MatrixBotAPI
    bot = MatrixBotAPI(USERNAME, PASSWORD, SERVER)

    # Set avatar / fix this later
    # bot.set_matrix_avatar(AVATAR_URL)
    
    # Hello testing handler 
    hello_handler = MCommandHandler("hello", hello_callback)
    bot.add_handler(hello_handler)
    
    # Host inspection handler
    hi_handler = MCommandHandler("hi", hi_callback)
    bot.add_handler(hi_handler)
    
    # Subdomain inspection handler 
    si_handler = MCommandHandler("si", si_callback)
    bot.add_handler(si_handler)
    
    # Help handler
    help_handler = MCommandHandler("helpmonty", help_callback)
    bot.add_handler(help_handler)
    
    # POST handler
    post_handler = MCommandHandler("post", post_callback)
    bot.add_handler(post_handler)
    
    # Start polling
    bot.start_polling()
    
    # Infinitely read stdin to stall main thread while the bot runs in other threads
    while True:
        input()

if __name__ == "__main__":
    main()

