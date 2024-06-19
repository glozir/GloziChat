import sys
import socket
import subprocess
import re
import requests
from bs4 import BeautifulSoup
import random
from datetime import datetime




def generate_random_happy_emoji():
    happy_emojis = [
        ":)", ":D", ";)", ":P", ":p", ":3", "^_^", "=)", "=]", "8)", ":-)", ":]", ":-D", ":}", ";-)", ";D", "X)", "xD", ";-D", "xD", "=D", "8D", "XD", ":')D", "^w^", "^_^;", "^-^", "^o^", "<(^_^<)", "(>^_^)>", "(*^_^*)", "(^._.^)ﾉ", "(^o^)/", "(^O^)／", "(^_^)v", "(^_-)-☆", "(^_^)/", "(^J^)", "(^_-)", "(＾ｖ＾)", "(・∀・)", "(｀・ω・´)", "(￣▽￣)", "(´∀`)", "(＾◡＾)"]

    return random.choice(happy_emojis)

# TODO: this is so dumb
def generate_random_color(min_brightness=128):
    # Generate random values for red, green, and blue
    r = random.randint(0, 255)
    g = random.randint(0, 255)
    b = random.randint(0, 255)

    # Calculate the brightness of the color using the formula (R + R + B) / 3
    brightness = (r + g + b) / 3

    # Check if the brightness is above the minimum threshold
    if brightness < min_brightness:
        # If not, adjust the color values to increase the brightness
        diff = min_brightness - brightness
        r += int(diff * (255 - r) / brightness)
        g += int(diff * (255 - g) / brightness)
        b += int(diff * (255 - b) / brightness)

    # Generate random values for red, green, and blue
    r = random.randint(0, 255)
    g = random.randint(0, 255)
    b = random.randint(0, 255)

    # Calculate the brightness level of the color
    brightness = (r * 299 + g * 587 + b * 114) / 1000

    # If the brightness level is too low, generate a new color
    if brightness < 128:
        return generate_random_color()

    # Return the color as a string in the form "#RRGGBB"
    return f"#{r:02x}{g:02x}{b:02x}"


def get_server_time(code : int = 0) -> str:
    '''


    '''
    if code:
        now = datetime.now()
        server_time = now.strftime("%H:%M:%S")
    else:
        now = datetime.now()
        server_time = now.strftime("%d/%m/%Y %H:%M:%S") 
    
    return server_time


def get_random_quotes(number_of_quotes: int) -> list[(str, str)]:
    '''

    '''

    # URL of the random quotes page
    quote_url = 'http://www.quotationspage.com/random.php'

    # GET quote page and check status code
    res = requests.get(quote_url)
    if res.status_code == 200:
        # Create soup
        page = BeautifulSoup(res.text, 'html.parser')

        # Find the quotes and authors
        quotes = page.find_all('dt', {'class': 'quote'})
        authors = page.find_all('dd', {'class': 'author'})
        quote_author_pairs = []

        # Pair the quotes and authors
        for i in range(len(quotes)):
            quote = '"' + quotes[i].text.strip() + '"'
            author = authors[i].find('b').text.strip()
            quote_author_pairs.append((quote, author))
    return quote_author_pairs[:number_of_quotes]


def get_host_ip() -> int:
    '''
    Using sockets gets the system ip.

    Returns:
    int: host ip 
    '''
    # ostname = socket.gethostname()
    # IPAddr = socket.gethostbyname(hostname)

    return "127.0.0.1"


def get_open_port() -> int:
    '''
    Using sockets finds an open port.

    Returns:
    int:open port 
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port


def get_broadcast_ip() -> str:
    ''' 
    Using subprocess and ipconfig gets broadcast ip. 

    Returns: 
    str:broadcast ip 
    '''

    # Get default encoding
    encoding = sys.getdefaultencoding()

    # Get ipconfig output
    output = subprocess.Popen('ipconfig', stdout=subprocess.PIPE).communicate()
    output = output[0].decode(encoding, errors='ignore')

    # Get the subnet mask and gateway ip
    match = re.search(
        r'Subnet Mask(?:\s+\.*)+:\s*(\d+\.\d+\.\d+\.\d+)\s+Default Gateway(?:\s+\.*)+:\s*(\d+\.\d+\.\d+\.\d+)', output)

    if match:
        subnet_mask = match.group(1)
        gateway_ip = match.group(2)

        # Calculate the broadcast ip
        gateway_octets = [int(octet) for octet in gateway_ip.split('.')]
        subnet_octets = [int(octet) for octet in subnet_mask.split('.')]
        broadcast_octets = [(gateway_octets[i] | (
            ~subnet_octets[i] & 0xFF)) for i in range(4)]
        broadcast_ip = '.'.join(str(octet) for octet in broadcast_octets)

    else:
        broadcast_ip = '255.255.255.255'

    return broadcast_ip
