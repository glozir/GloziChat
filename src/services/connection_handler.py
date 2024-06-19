import socket
import random
import time 
import select
import pickle
import re

from ..utils.consts import DEFAULT_ROOM_NAMES, RANDOM_QUOTES, HELP_MESSAGE, INACTIVE_TIME, BUFSIZ
from ..utils.utils import get_server_time, get_random_quotes

import logging

# Step 2: Configure the logging settings
logging.basicConfig(
    level=logging.DEBUG,  # Set the logging level
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Define the log format
    handlers=[
        logging.FileHandler('app.log'),  # Log to a file named 'app.log'
        logging.StreamHandler()  # Optional: Also log to the console
    ]
)

# Step 3: Create a logger
logger = logging.getLogger(__name__)

class ConnectionHandler(): 
    def __init__(self, server) -> None:
        self.sessions = {}
        self.client_to_session = {}
        self.session_count = 0 
        self.server = server 

        self.connection_list = [self.server]

    def run(self):
        self.handle_connections()

    def create_session(self, session_name: str = None, password: int = 'NO CODE', admin: socket.socket = 'server_host') -> int:
        '''
        Creates a new chat session and adds it to the sessions dictionary.

        Parameters:
            session_name (str): The name of the session. If not specified, a random name is chosen from the list of random room names.
            password (int): The password of the session. If not specified, set to 'NO CODE'.
            admin (socket): The socket of the session's administrator. If not specified, set to 'server_host'.

        Returns:
            int: The number of the session.


        '''
        # If session name is not provided, choose a random name from the list of random room names
        if not session_name and DEFAULT_ROOM_NAMES:
            random_name = random.choice(DEFAULT_ROOM_NAMES)
            DEFAULT_ROOM_NAMES.remove(random_name)
            session_name = random_name

        # Increment the number of sessions and add the new session to the sessions dictionary
        self.session_count += 1
        self.sessions[self.session_count] = {
            'session_name': session_name,  # str - name of the session
            'clients': [],  # <sock> - client sockets connected to the session
            'client_names': {},  # <sock> : '<name>' - a dictionary of client sockets, names pairs
            'warned_inactive': [],  # '<name>' - clients who were warned for inactivity (default inactivity warning time 2 min)
            'last_active': {},  # '<name>' : <last_active_time> - last time each client was active
            'join_time': {},  # '<name>' : <join_time> - join session time
            'password': password,  # int - password of the session (currently no passwords) range 10000 - 99999
            'session_id': self.session_count,  # int - session id (currently set to number of the session)
            'creation_time': get_server_time(1),  # the time the session was created
            'creator': 'server_host',  # the creator of the session
            'admin': admin  # the socket of the session's administrator
        }

        return self.session_count

    def handle_command(self, command: str, sock: socket.socket, session: dict) -> str:
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
                quote = RANDOM_QUOTES.pop()
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
                            self.disconnect(kicked_member, 4)
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
                self.disconnect(sock)
                return
            else:
                return "chat/system/quit command does not take additional parameters. Enter /help for additional information."

        # Process help command
        elif parts[0] == '/help':
            if len(parts) == 1:
                return f"chat/system/{HELP_MESSAGE}"
            else:
                return "chat/system/help command does not take additional parameters."

        elif parts[0] == '/file':
            if len(parts) == 1:
                return f"chat/system/{HELP_MESSAGE}"
            else:
                msg = f'chat/server/{self.sessions[self.client_to_session[sock]]['client_names'][sock]} shared the file: {parts[2]}, to download type /download -filename-'
                self.broadcast_msg(self.server, msg.encode(), self.client_to_session[sock])

        # Process close command
        elif parts[0] == '/close':
            if len(parts) == 1:
                if sock == session.get('admin'):
                    msg = 'chat/system/the ADMIN has closed the session'
                    self.broadcast_msg(self.server, msg.encode(), self.client_to_session[sock])
                    for client in session['clients']:
                        self.disconnect(client, 3)
                    del self.sessions[self.client_to_session[sock]]
                else:
                    return "chat/system/missing ADMIN privileges. Enter /help for additional information."
            else:
                return "chat/system/quit command does not take additional parameters. Enter /help for additional information."
        else: 
            return f'chat/system/unkonwn command. enter /help for additional information.'

    def time_out(self) -> None:
        '''
        Check if clients have been inactive for too long and disconnect them if so.
        
        Args:
            None.
        
        Returns: 
            None.
        '''
        # Create a list of all clients' last active times and warnings
        all_last_active = []
        for session in self.sessions.values():
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
                        self.disconnect(client, 2)

    def disconnect(self, client: socket.socket, code: int = 0) -> None:
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
        print("helllo", code, client)

        # If client was connected to a session
        session_id = self.client_to_session.get(client)

        if session_id and code != 3:
            session = self.sessions[session_id]
            
            del session['clients'][session['clients'].index(client)]

            if session['clients'] or session['admin'] == 'server_host':
                # Determine if the admin has left, and if so choose a new admin randomly
                if session['admin'] == client:
                    new_admin = random.choice(session['clients'])
                    session['admin'] = new_admin
                    # Notify the remaining clients that a new admin has been chosen
                    self.broadcast_msg(
                        client, f'admin_left/{session["client_names"][client]}/new/{session["client_names"][session["admin"]]}'.encode(), session_id)
                # Notify the remaining clients that a user has left, timed out, or been kicked out
                elif code == 4:
                    self.broadcast_msg(
                        client, f'user_kicked/{session["client_names"][client]}'.encode(), session_id)
                elif code == 2:
                    self.broadcast_msg(
                        client, f'user_timeout/{session["client_names"][client]}'.encode(), session_id)
                elif code == 1:
                    self.broadcast_msg(
                        client, f'user_left/{session["client_names"][client]}'.encode(), session_id)
                else:
                    self.broadcast_msg(
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
                del self.sessions[session_id]

        # Remove client from active connection lists and close the connection
        if client in self.write_sockets:
            self.write_sockets.remove(client)
        if client in self.connection_list:
            self.connection_list.remove(client)
        client.close()

    def broadcast_msg(self, sender_socket: socket.socket, msg: str, session_id: int = 1) -> None:
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
        for sock in self.sessions[session_id]['clients']:
            # Only send the message to other clients (not the server or the sender socket)
            if sock != sender_socket and sock in self.write_sockets:
                try:
                    # Send the message
                    sock.send(msg)
                except (ConnectionResetError, Exception) as E:
                    print("rip", E)
                    # If there is a connection issue, close the socket and remove it from the connection list
                    self.disconnect(sock, 1)
                    continue

    def handle_connections(self) -> None:
        '''
        Handles incoming connections from clients and creates sessions.

        Args:
            server_socket (): the server's socket.
            
        Returns:
            None.
        '''

        # Bind the server socket
        self.server.listen(5)
        self.server.setblocking(0)

        print('---Server is running---')

        # Create 9 sessions on server start
        for i in range(9):
            self.create_session()

        # password for closing the server 
        close_server_password = random.randint(10000,99999)
        print('to close the server enter code:', close_server_password)

        while True:
            # Get the list sockets which are ready to be read or write through select
            self.read_sockets, self.write_sockets, error_sockets = select.select(
                self.connection_list, self.connection_list, [])

            # Loop over sockets and accept new connections
            for sock in self.read_sockets:
                if sock == self.server:
                    new_socket, address = sock.accept()
                    #print('Connect:', address, id(new_socket))
                    self.connection_list.append(new_socket)
                else:
                    try:
                        data = sock.recv(BUFSIZ).decode()

                        if not data:
                            self.disconnect(sock)

                        else:
                            # Check if client has a session
                            if sock not in self.client_to_session.keys():
                                
                                # If client requests for session info
                                if data == 'reload/sessions':
                                    sessions_info = []
                                    for session in self.sessions.values():
                                        no_code = ' | NO CODE' if session['password'] == 'NO CODE' else ''
                                        sessions_info.append(
                                            (f'name: {session["session_name"]} | active users: {len(session["clients"])} | creator: {session["creator"]} | creation time: {session["creation_time"]} | session id: {session["session_id"]}' + no_code))

                                    sessions_info = pickle.dumps(sessions_info)

                                    # Send info if in write sockets
                                    if sock in self.write_sockets:
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
                                    session = self.sessions.get(session_id)

                                    # check if password is ok and username is not taken
                                    if session and session['password'] == password and username not in session['client_names'].values():
                                        session['clients'].append(sock)
                                        session['client_names'][sock] = username
                                        session['last_active'][sock] = time.time()
                                        session['join_time'][sock] = get_server_time(1)
                                        self.client_to_session[sock] = session['session_id']
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
                                    self.broadcast_msg(
                                        sock, f'user_joined/{username}/{session["join_time"][sock]}'.encode(), self.client_to_session[sock])

                                # Check for valid session creation request 
                                elif match := re.search(r'^create\/((?!\d)[a-zA-Z0-9]{3,12})\/name\/((?!\d)[a-zA-Z0-9]{3,12})\/([0-9]{5,5}|NO CODE)$', data):
                                    
                                    # Extract  username, session name, and password from login request
                                    session_name = match.group(1)
                                    username = match.group(2)
                                    password = match.group(3)
                                    if password.isdigit():
                                        password = int(password)

                                    # Create the new session
                                    session_id = self.create_session(
                                        session_name, password, sock)
                                    session = self.sessions.get(session_id)

                                    # configure the new session and add the client 
                                    session['clients'].append(sock)
                                    session['client_names'][sock] = username
                                    session['last_active'][sock] = time.time()
                                    session['join_time'][sock] = get_server_time(1)
                                    session['creator'] = username
                                    self.client_to_session[sock] = session['session_id']
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
                                        for session in self.sessions.values():
                                            msg = 'chat/system/the server has been closed'
                                            self.broadcast_msg(self.server, msg.encode(), session['session_id'])
                                            for client in session['clients']:
                                                self.disconnect(client, 3)
                                        exit()
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
                                session = self.sessions[self.client_to_session[sock]]

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
                                        command_result = self.handle_command(data, sock, session)
                                        if command_result:
                                            sock.send(command_result.encode())
                                    # If the message does not contain a command, broadcast it to other clients in the session
                                    else:
                                        # Create message to be broadcasted
                                        msg = f'chat/{session["client_names"][sock]}/{data}'
                                        self.broadcast_msg(sock, msg.encode(), self.client_to_session[sock])
                        
                    # In case of connection error, disconnect the client
                    except (ConnectionResetError, Exception) as E:
                        print(E, "ERROR?")
                        self.disconnect(sock, 1)
                        
            # Check for inactive clients and disconnect them
            self.time_out()
