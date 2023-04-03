# Import necessary modules and functions
from datetime import datetime
import time
import re
import pickle
import json
from select import select
from utils import *
from scapy.all import *
from scapy.all import IP, ICMP
from threading import Thread
from scapy.all import conf as scapyconf

# Disable Scapy promiscuous mode to avoid crashes 
scapyconf.sniff_promisc = 0

# --- Network Configuration --- 

# Define host IP address, TCP port, and buffer size
HOST = ''
HOST_IP = get_host_ip()
TCP_PORT = get_open_port()
BUFSIZ = 4096  

# --- Session Configuration --- 

# Session handling
sessions = {}
num_of_sessions = 0
client_session = {}

# Inactive time before server disconnects user
INACTIVE_TIME = 240  

# Connection list of all clients connected to the server and server 
CONNECTION_LIST = []

# Default room names
randon_room_names = ['avocado', 'kiwi', 'pineapple', 'krembo',
                     'watermelon', 'papaya', 'coconut', 'Passiflora', 'cactus']

# Randomly generated quotes
random_quotes = get_random_quotes(10)

# Help command message
help_message = """
Available Commands:
- /quote: returns a random quote
- /time: returns the current server time
- /echo [text]: echoes the provided text back to the user
- /kick [member]: kicks the specified member from the session (admin-only)
- /quit: disconnects the user from the session
- /close: closes the session (admin-only)

To use a command, type the command name followed by any required parameters (if any).
For example, to echo the message 'hello', type '/echo hello'."""      


# --- Main Program ---

def send_server_info(packet: Packet) -> None:
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
                data_to_send = json.dumps({'ip': HOST_IP, 'port': TCP_PORT})

                # Send the data to the client
                s.sendto(data_to_send.encode(),
                         (client_data['ip'], client_data['port']))
    except:
        # If an exception occurs, ignore it and exit 
        return


def answer_client_echo() -> None:
    '''
    Listens for ICMP echo requests from clients and sends system information back.

    Args:
        None.

    Returns:
        None.
    '''
    # Listen for ICMP echo requests from clients and call send_server_info for each packet
    pkts = sniff(filter='icmp[icmptype] == icmp-echo', prn=send_server_info)


def create_session(session_name: str = f'place_holder', password: int = 'NO CODE', admin: socket = 'server_host') -> int:
    '''
    Creates a new chat session and adds it to the sessions dictionary.

    Parameters:
        session_name (str): The name of the session. If not specified, a random name is chosen from the list of random room names.
        password (int): The password of the session. If not specified, set to 'NO CODE'.
        admin (socket): The socket of the session's administrator. If not specified, set to 'server_host'.

    Returns:
        int: The number of the session.


    '''
    global num_of_sessions

    # If session name is not provided, choose a random name from the list of random room names
    if session_name == 'place_holder' and randon_room_names:
        random_name = random.choice(randon_room_names)
        randon_room_names.remove(random_name)
        session_name = random_name

    # Increment the number of sessions and add the new session to the sessions dictionary
    num_of_sessions += 1
    sessions[num_of_sessions] = {
        'session_name': session_name,  # str - name of the session
        'clients': [],  # <sock> - client sockets connected to the session
        'client_names': {},  # <sock> : '<name>' - a dictionary of client sockets, names pairs
        'warned_inactive': [],  # '<name>' - clients who were warned for inactivity (default inactivity warning time 2 min)
        'last_active': {},  # '<name>' : <last_active_time> - last time each client was active
        'join_time': {},  # '<name>' : <join_time> - join session time
        'password': password,  # int - password of the session (currently no passwords) range 10000 - 99999
        'session_id': num_of_sessions,  # int - session id (currently set to number of the session)
        'creation_time': get_server_time(1),  # the time the session was created
        'creator': 'server_host',  # the creator of the session
        'admin': admin  # the socket of the session's administrator
    }

    return num_of_sessions


def handle_command(command: str, sock: socket.socket, session: dict) -> str:
    """
    Process a command received from a client.

    Args:
        command (str): The command received from the client.
        sock (socket.socket): The client's socket connected to the server.
        session (dict): The session dictionary containing information about the current session.

    Returns:
        str: A message to be sent back to the client.
    """
    parts = command.split()

    # Process quote command
    if parts[0] == '/quote':
        if len(parts) == 1:
            if len(random_quotes) == 0:
                random_quotes.extend(get_random_quotes(10))
            quote = random.choice(random_quotes)
            random_quotes.remove(quote)
            return f"chat/server/{' '.join(quote)}"
        else:
            return "chat/system/quote command does not take additional parameters. Enter /help for additional information."

    # Process time command
    elif parts[0] == '/time':
        if len(parts) == 1:
            return f"chat/server/{get_server_time()}"
        else:
            return "chat/system/time command does not take additional parameters. Enter /help for additional information."

    # Process echo command
    elif parts[0] == '/echo':
        if len(parts) > 1:
            return f"chat/server/echo -> {' '.join(parts[1:])}"
        else:
            return "chat/system/echo command missing text to be echoed. Enter /help for additional information."

    # Process kick command
    elif parts[0] == '/kick':
        if sock == session.get('admin'):
            if len(parts) == 2:
                kicked_member_name = parts[1]
                kicked_member = next((c for c, n in session['client_names'].items() if n == kicked_member_name), None)
                if kicked_member:
                    if kicked_member != sock:
                        kicked_member.send('chat/system/you were kicked by the ADMIN.'.encode())
                        disconnect(kicked_member, 4)
                    else:
                        return 'chat/system/you cannot kick yourself.'
                else:
                    return f"chat/system/member '{kicked_member_name}' does not exist in this session. Enter /help for additional information."
            else:
                return "chat/system/kick command missing member to be kicked or too many parameters. Enter /help for additional information."
        else:
            return "chat/system/missing ADMIN privileges. Enter /help for additional information."

    # Process quit command
    elif parts[0] == '/quit':
        if len(parts) == 1:
            sock.send("chat/system/the server has disconnected you".encode())
            disconnect(sock)
            return
        else:
            return "chat/system/quit command does not take additional parameters. Enter /help for additional information."

    # Process help command
    elif parts[0] == '/help':
        if len(parts) == 1:
            return f"chat/system/{help_message}"
        else:
            return "chat/system/help command does not take additional parameters."

    # Process close command
    elif parts[0] == '/close':
        if len(parts) == 1:
            if sock == session.get('admin'):
                msg = 'chat/system/the ADMIN has closed the session'
                broadcast_msg(server, msg.encode(), client_session[sock])
                for client in session['clients']:
                    disconnect(client, 3)
                del sessions[client_session[sock]]
            else:
                return "chat/system/missing ADMIN privileges. Enter /help for additional information."
        else:
            return "chat/system/quit command does not take additional parameters. Enter /help for additional information."
    else: 
       return f'chat/system/unkonwn command. enter /help for additional information.'


def time_out() -> None:
    '''
    Check if clients have been inactive for too long and disconnect them if so.
    
    Args:
        None.
    
    Returns: 
        None.
    '''
    # Create a list of all clients' last active times and warnings
    all_last_active = []
    for session in sessions.values():
        all_last_active.append(
            (session['last_active'].copy(), session['warned_inactive'], session['admin']))

    # Check each client's last active time and disconnect them if they have been inactive for too long
    for last_active, warned_inactive, admin in all_last_active:
        for client, last_active_time in last_active.items():
            # Don't disconnect the admin for inactivity
            if client is not admin:
                # Calculate time inactive
                time_inactive = time.time() - last_active_time
                # Warn user about disconnection if they haven't been warned yet
                if time_inactive >= INACTIVE_TIME/2 and client not in warned_inactive:
                    client.send(
                        f'chat/server/{(INACTIVE_TIME//2)//60} min till disconnection'.encode())
                    warned_inactive.append(client)
                # Disconnect user if they have been inactive for too long
                elif time_inactive >= INACTIVE_TIME:
                    client.send(
                        'timeout/server/you are disconnected from the server for inactivity!'.encode())
                    disconnect(client, 2)


def disconnect(client: socket.socket, code: int = 0) -> None:
    '''
    Disconnects a client from the server, removes them from the active connection list and any active sessions.

    Args: 
        client (socket):  socket of the client to be disconnected.
        code (int):  representing the reason for the disconnect.
            0 - client disconnected normally.
            1 - client crashed.
            2 - client timed out.
            3 - server is shutting down.
            4 - client was kicked out of session by admin.
    Returns:
        None.
    '''

    # If client was connected to a session
    session_id = client_session.get(client)

    if session_id and code != 3:
        session = sessions[session_id]
        
        del session['clients'][session['clients'].index(client)]

        if session['clients'] or session['admin'] == 'server_host':
            # Determine if the admin has left, and if so choose a new admin randomly
            if session['admin'] == client:
                new_admin = random.choice(session['clients'])
                session['admin'] = new_admin
                # Notify the remaining clients that a new admin has been chosen
                broadcast_msg(
                    client, f'admin_left/{session["client_names"][client]}/new/{session["client_names"][session["admin"]]}'.encode(), session_id)
            # Notify the remaining clients that a user has left, timed out, or been kicked out
            elif code == 4:
                #print(client.getpeername(), 'has been kicked out')
                broadcast_msg(
                    client, f'user_kicked/{session["client_names"][client]}'.encode(), session_id)
            elif code == 2:
                #print(client.getpeername(), 'has timed out')
                broadcast_msg(
                    client, f'user_timeout/{session["client_names"][client]}'.encode(), session_id)
            elif code == 1:
                #print(client.getpeername(), 'has crashed')
                broadcast_msg(
                    client, f'user_left/{session["client_names"][client]}'.encode(), session_id)
            else:
                #print(client.getpeername(), 'has disconnected')
                broadcast_msg(
                    client, f'user_left/{session["client_names"][client]}'.encode(), session_id)

            # Remove client from session dictionaries
            del session['client_names'][client]
            del session['join_time'][client]
            del session['last_active'][client]

            # Remove client from warned_inactive list if necessary
            if client in session['warned_inactive']:
                del session['warned_inactive'][session['warned_inactive'].index(
                    client)]
        else:
            # If session has no more clients, delete the session
            del sessions[session_id]

    # Remove client from active connection lists and close the connection
    if client in write_sockets:
        write_sockets.remove(client)
    if client in CONNECTION_LIST:
        CONNECTION_LIST.remove(client)
    client.close()


def broadcast_msg(sender_socket: socket.socket, msg: str, session_id: int = 1) -> None:
    '''
    Sends a message to all clients in a given session except for the sender socket.

    Args:
        sender_socket (socket.socket): The socket that sent the message.
        msg (str): The message to be broadcasted.
        session_id (int): The id of the session to which the message will be broadcasted (default 1).

    Returns:
        None.
    '''
    # Loop over all sockets in the session
    for sock in sessions[session_id]['clients']:
        # Only send the message to other clients (not the server or the sender socket)
        if sock != sender_socket and sock in write_sockets:
            try:
                # Send the message
                sock.send(msg)
            except (ConnectionResetError, Exception):
                # If there is a connection issue, close the socket and remove it from the connection list
                disconnect(sock, 1)
                continue


def handle_connections(server_socket: socket.socket) -> None:
    '''
    Handles incoming connections from clients and creates sessions.

    Args:
        server_socket (): the server's socket.
        
    Returns:
        None.
    '''
    global write_sockets

    # Bind the server socket
    server_socket.bind((HOST, TCP_PORT))
    server_socket.listen(5)
    server_socket.setblocking(0)

    print('---Server is running---')

    # Create 9 sessions on server start
    for i in range(9):
        create_session()

    # password for closing the server 
    close_server_password = random.randint(10000,99999)
    print('to close the server enter password:', close_server_password)

    while True:
        # Get the list sockets which are ready to be read or write through select
        read_sockets, write_sockets, error_sockets = select.select(
            CONNECTION_LIST, CONNECTION_LIST, [])

        # Loop over sockets and accept new connections
        for sock in read_sockets:
            if sock == server_socket:
                new_socket, address = sock.accept()
                #print('Connect:', address, id(new_socket))
                CONNECTION_LIST.append(new_socket)
            else:
                try:
                    data = sock.recv(BUFSIZ).decode()

                    if not data:
                        disconnect(sock)

                    else:
                        # Check if client has a session
                        if sock not in client_session.keys():
                            
                            # If client requests for session info
                            if data == 'reload/sessions':
                                sessions_info = []
                                for session in sessions.values():
                                    no_code = ' | NO CODE' if session['password'] == 'NO CODE' else ''
                                    sessions_info.append(
                                        (f'name: {session["session_name"]} | active users: {len(session["clients"])} | creator: {session["creator"]} | creation time: {session["creation_time"]} | session id: {session["session_id"]}' + no_code))

                                sessions_info = pickle.dumps(sessions_info)

                                # Send info if in write sockets
                                if sock in write_sockets:
                                    sock.send(sessions_info)
                                continue

                            # Check for valid login request
                            if match := re.search(r'^login\/name\/((?!\d)[a-zA-Z0-9]{3,12})\/((?!0)[1-9]\d*)\/([0-9]{5,5}|NO CODE)$', data):
                                # Name of the new client and session number
                                username = match.group(1)
                                session_id = int(match.group(2))
                                password = match.group(3)
                                if password.isdigit():
                                    password = int(password)
                                session = sessions.get(session_id)

                                # check if password is ok and username is not taken
                                if session and session['password'] == password and username not in session['client_names'].values():
                                    session['clients'].append(sock)
                                    session['client_names'][sock] = username
                                    session['last_active'][sock] = time.time()
                                    session['join_time'][sock] = get_server_time(1)
                                    client_session[sock] = session['session_id']
                                    #print(f'{username} has successfuly signed in to session {session["session_id"]}')
                                else:
                                    sock.send('IN-400'.encode())
                                    continue

                                # Send the client a dict of users in the session + join time of each user 
                                users_joined = {}
                                for sock, join_time in session['join_time'].items():
                                    users_joined[session['client_names']
                                                 [sock]] = join_time

                                if session['admin'] != 'server_host':
                                    data = (
                                        users_joined, session['client_names'][session['admin']])
                                else:
                                    data = (users_joined, session['admin'])

                                # Send successful sign in to client
                                sock.send('IN-200'.encode() +
                                          pickle.dumps(data))

                                # Send broadcast to everyone about the new user
                                broadcast_msg(
                                    sock, f'user_joined/{username}/{session["join_time"][sock]}'.encode(), client_session[sock])

                            # Check for valid session creation request 
                            elif match := re.search(r'^create\/((?!\d)[a-zA-Z0-9]{3,12})\/name\/((?!\d)[a-zA-Z0-9]{3,12})\/([0-9]{5,5}|NO CODE)$', data):
                                
                                # Extract  username, session name, and password from login request
                                session_name = match.group(1)
                                username = match.group(2)
                                password = match.group(3)
                                if password.isdigit():
                                    password = int(password)

                                # Create the new session
                                session_id = create_session(
                                    session_name, password, sock)
                                session = sessions.get(session_id)

                                # configure the new session and add the client 
                                session['clients'].append(sock)
                                session['client_names'][sock] = username
                                session['last_active'][sock] = time.time()
                                session['join_time'][sock] = get_server_time(1)
                                session['creator'] = username
                                client_session[sock] = session['session_id']
                                #print(f'{username} has successfuly signed in to session {session["session_id"]}')
                                
                                # Send the client a dict of users in the session + join time of each user 
                                users_joined = {}
                                for sock, join_time in session['join_time'].items():
                                    users_joined[session['client_names']
                                                 [sock]] = join_time

                                # Send successful sign in to client
                                sock.send('IN-200'.encode() +
                                          pickle.dumps(users_joined))
                            
                            # Check for valid close request
                            elif match := re.search(r'^close\/([0-9]{5,5})$', data):
                                    
                                # Extract password
                                password = int(match.group(1))
                                
                                # if password is close server password, disconnect all users and exit the program 
                                if password == close_server_password:
                                    for session in sessions.values():
                                        msg = 'chat/system/the server has been closed'
                                        broadcast_msg(server, msg.encode(), session['session_id'])
                                        for client in session['clients']:
                                            disconnect(client, 3)
                                    sys.exit()
                                else:
                                    # password is incorrect 
                                    sock.send('IN-400'.encode())  
                            elif data == 'check_connectivity': 
                                continue
                            else:
                                # Send request is unkown  
                                sock.send('IN-400'.encode())  
                            continue
 



                        # If the client has joined a session, process the data as a message
                        else:
                            # Get the session of the current client
                            session = sessions[client_session[sock]]

                            # Update last active time and remove from warned inactive if needed
                            session['last_active'][sock] = time.time()
                            if sock in session['warned_inactive']:
                                session['warned_inactive'].remove(sock)

                            # Handle messages sent in the chat by the user
                            if data.startswith('chat/'):
                                data = data[5:]

                                # If the message contains a command
                                if data[0] == '/':
                                    # Handle the command
                                    command_result = handle_command(data, sock, session)
                                    if command_result:
                                        sock.send(command_result.encode())
                                # If the message does not contain a command, broadcast it to other clients in the session
                                else:
                                    # Create message to be broadcasted
                                    msg = f'chat/{session["client_names"][sock]}/{data}'
                                    broadcast_msg(sock, msg.encode(), client_session[sock])
                    
                # In case of connection error, disconnect the client
                except (ConnectionResetError, Exception) as E:
                    #print(E, "ERROR?")
                    disconnect(sock, 1)
                    
        # Check for inactive clients and disconnect them
        time_out()


if __name__ == '__main__':
    # Create a thread that will handle client echos
    answer_echos_thread = Thread(target=answer_client_echo)
    answer_echos_thread.daemon = True
    answer_echos_thread.start()

    # Create server socket, connection_list and start handling client connections
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    CONNECTION_LIST.append(server)
    handle_connections(server)
    server.close()
