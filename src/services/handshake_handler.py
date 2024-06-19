
import socket 
import json

from scapy.sendrecv import sniff, send
from scapy.packet import Packet, Raw
from scapy.config import conf as scapyconf
from scapy.layers.inet import ICMP, IP  
from threading import Thread

from ..utils.consts import BUFSIZ, BROADCAST_IP

# Disable Scapy promiscuous mode to avoid crashes 
scapyconf.sniff_promisc = 0
scapyconf.verb = 0 


class EchoHandler: 
    def __init__(self, ip, port) -> None:
        self.ip = ip 
        self.port = port 
        self.connection_request_thread = Thread(target=self.answer_echo)
        self.connection_request_thread.daemon = True

    def run(self) -> None: 
        self.connection_request_thread.start()
    
    def answer_echo(self) -> None:
        '''
        Listens for ICMP echo requests from clients and sends system information back.

        Args:
            None.

        Returns:
            None.
        '''
        # Listen for ICMP echo requests from clients and call send_server_info for each packet
        print("start sniffing...")
        pkts = sniff(filter='icmp', prn=self.send_info)

    def send_info(self, packet: Packet) -> None:
        '''
        Sends system information back to the client who made an ICMP echo request.

        Args:
            packet (Packet): The Scapy packet containing the ICMP echo and Raw layers.

        Returns:
            None.
        '''
        try:
            # Check if packet has both ICMP and Raw layers
            if packet and packet.haslayer(ICMP) and packet.haslayer(Raw):
                # Check if ICMP request is of type 8 (echo request)
                if packet[ICMP].type == 8:
                    # Decode the client data from the Raw layer and convert it to JSON
                    client_data = packet[Raw].load.decode()
                    client_data = json.loads(client_data)

                    # Create a UDP socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                    # Create data to send back to the client containing the server's IP address and TCP port
                    data_to_send = json.dumps({'ip': self.ip, 'port': self.port})

                    # Send the data to the client
                    s.sendto(data_to_send.encode(),
                            (client_data['ip'], client_data['port']))
        except:
            # If an exception occurs, ignore it and exit 
            return
        

class ServerFinder:
    def __init__(self, ip, port) -> None:
        self.ip = ip 
        self.port = port 

    def connect(self): 
        ip, port = self.search()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))

        return sock

    def search(self):
        '''
        This function connects to the server by sending a broadcasted ping to find the server
        and then waiting for the server to respond with its IP and port.
        
        Args:
            None.   
        
        Returns: 
            socket: client socket connected to the server.
            
        
        '''

        # Create IP and ICMP packets and encode message
        ip_packet = IP(dst=BROADCAST_IP)
        ping_packet = ICMP()
        data = json.dumps({'ip': self.ip, 'port': self.port}).encode()

        # Combine the ICMP packet and message into a single packet and send it
        packet = ip_packet / ping_packet / data
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('', self.port))
            s.settimeout(1)
            #print(f"Listening on port {UDP_PORT}...")
            while True:
                print(packet)
                send(packet, verbose=False)

                try:
                    # Wait for the server response
                    data, addr = s.recvfrom(BUFSIZ)
                    data = json.loads(data.decode())

                    # Connect to the server using TCP
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.connect((data['ip'], data['port']))
                    
                    return data['ip'],  data['port']

                except socket.timeout:
                    continue

                except Exception as e:
                    continue
            