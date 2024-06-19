from .utils import get_broadcast_ip, get_host_ip, get_random_quotes

INACTIVE_TIME = 240 
BUFSIZ = 4096
BROADCAST_IP = get_broadcast_ip()
HOST_IP = get_host_ip()
DEFAULT_ROOM_NAMES = ['avocado', 'kiwi', 'pineapple', 'krembo',
                     'watermelon', 'papaya', 'coconut', 'Passiflora', 'cactus']

class RandomQuote:
    def __init__(self) -> None:
        self.quotes = []
    
    def extended(self):
        self.quotes += get_random_quotes(10)

    def pop(self, index):
        if not len(self.quotes):  
            self.extended()

        return self.quotes.pop() 

RANDOM_QUOTES = RandomQuote()
HELP_MESSAGE = """
Available Commands:
- /quote: returns a random quote
- /time: returns the current server time
- /echo [text]: echoes the provided text back to the user
- /kick [member]: kicks the specified member from the session (admin-only)
- /quit: disconnects the user from the session
- /close: closes the session (admin-only)

To use a command, type the command name followed by any required parameters (if any).
For example, to echo the message 'hello', type '/echo hello'."""      

