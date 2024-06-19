import socket

from .handshake_handler import EchoHandler
from .connection_handler import ConnectionHandler
from ..utils.utils import get_host_ip, get_open_port


class Server(socket.socket): 
    def __init__(self, ip, port) -> None:
            super().__init__(socket.AF_INET, socket.SOCK_STREAM)

            self.ip = ip 
            self.port = port
            self.echo_handler = EchoHandler(self.ip, self.port)    
            self.connection_handler = ConnectionHandler(self)
            
            self.bind((ip, port))
            self.listen(5)
            self.setblocking(0)

            
    def run(self): 
        self.echo_handler.run()
        self.connection_handler.run()


def create_server():
    return Server("127.0.0.1", get_open_port())