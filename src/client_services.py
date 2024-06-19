import json
import socket
import time 
import tkinter as tk 
import pickle
import sys
import threading
import queue
import os


from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send
from tkinter import *
import tkinter.filedialog as fd
from tkinter import font, ttk
from PIL import Image, ImageTk
from threading import Thread
#import tkFileDialog as filedialog

from .utils.utils import *
from .services.handshake_handler import ServerFinder

# Set Discord-inspired colors
DISCORD_DARK_BLUE = "#2C2F33"
DISCORD_GRAY = "#2f3136"
DISCORD_BLUE = "#7289DA"
DISCORD_LIGHT_GRAY = "#36393f"
DISCORD_WHITE = "#FFFFFF"
BACKGROUND_COLOR = "#313338"
PRIMARY_COLOR = "#5865F2"
SECONDARY_COLOR = "#99AAB5"
TEXT_COLOR = "#B5BAC1"
ENTRY_COLOR = "#1E1F22"

# --- Network Configuration --- 

# Define broadcast IP address, host IP, UDP port, and buffer size 
BROADCAST_IP = get_broadcast_ip()
HOST_IP = get_host_ip()
UDP_PORT = get_open_port()
BUFSIZ = 4096


# --- User Interface Configuration --- 

# Create dictionary to store user colors
user_colors = {}  # name : color

# Define color scheme for system 
user_colors['system'] = 'red'

# Define global variables for message numbering 
message_number = 0
message_number_client = 0

# Create dictionary to store active users and their associated labels
users_active = {}  # name : label

# Define global variables for the user's name and the admin user
my_name = ''
ADMIN = ''

# Define variables for checking server connectivity 
stop_checking = False
stop_checking_temp = False

# --- Main Program ---

def set_admin(admin_name: str) -> None:
    '''
    Set the new admin and update their label.
    '''
    users_active[admin_name].config(text=f'Admin {users_active[admin_name].cget("text")}')


def connect() -> socket.socket:
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
    data = json.dumps({'ip': HOST_IP, 'port': UDP_PORT}).encode()

    # Combine the ICMP packet and message into a single packet and send it
    packet = ip_packet / ping_packet / data
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('', UDP_PORT))
        s.settimeout(1)
        #print(f"Listening on port {UDP_PORT}...")
        while True:
            send(packet, verbose=False)

            try:
                # Wait for the server response
                data, addr = s.recvfrom(BUFSIZ)
                data = json.loads(data.decode())

                # Connect to the server using TCP
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((data['ip'], data['port']))
                
                return client

            except socket.timeout:
                #print('Server took too long to respond echoing again')
                continue

            except Exception as e:
                #print(f"Error connecting to the server: {e}")
                continue


def receive(client: socket.socket, chat_screen : tk.Text) -> None:
    """Listen for incoming messages from the server and handle them appropriately.

    Args:
        client (socket.socket): The client socket connected to the server.
        chat_screen (tk.Text): The tkinter Text widget representing the chat display in the GUI.            
    Returns:
        None.

    """
    global ADMIN, user_colors, users_active

    while True:
        try:
            # Receive data from the server
            data = client.recv(BUFSIZ).decode()

            # Check if the server has disconnected
            if not data:
                print('server has disconnected')
                close_client(1)
                break

            # Handle disconnection message
            if data == 'you are disconnected from the server!':
                print(data)
            # Handle chat message
            elif data.startswith('chat/'):
                name, message = data.split('/', 2)[1:]
                # If the message is from the admin, add "ADMIN" to the name
                name = f'ADMIN {name}' if name == ADMIN else name
                # Update the chat window
                display_message(chat_screen, message, name)

            # Handle user joining message
            elif data.startswith('user_joined/'):
                name, join_time = data.split("/")[1:]
                # Update the chat window
                display_message(chat_screen, f'{name} has entered the chat room', 'system')
                # Generate a random color for the user
                user_colors[name] = generate_random_color()
                # Create a label for the user and add it to the active users tab
                user = tk.Label(users, text=f'{name} - {join_time} ',
                                fg=user_colors[name], font=("Helvetica", 12),
                                background=DISCORD_DARK_BLUE)
                user.pack(pady=5)
                users_active[name] = user

            # Handle user leaving, kicked or timed out message
            elif data.startswith('user_left/') or data.startswith('user_kicked/') or data.startswith('user_timeout/'):
                action, name = data.split("/")
                # Determine the type of action (left, been kicked or timed out) from the message type
                action = {'user_left': 'left', 'user_kicked': 'been kicked by the ADMIN from', 'user_timeout': 'been timed out'}[action]
                # Update the chat window
                display_message(chat_screen, f'{name} has {action} the chat room', 'system')
                # Remove the user from the active users tab
                users_active[name].destroy()
                del users_active[name]
                del user_colors[name]
                
            # Handle client timeout message
            elif data.startswith('timeout/'):
                _, room, message = data.split('/')
                # Update the chat window
                display_message(chat_screen, message, room)
                close_client(2)

            # Handle admin leaving message
            elif data.startswith('admin_left'):
                _, old_admin, _, new_admin = data.split('/')
                # Update the chat window
                display_message(chat_screen, f'ADMIN {old_admin} left the chat room, {new_admin} is the new ADMIN now', 'system')
                # Remove the old admin from the active users tab and set the new admin
                users_active[old_admin].destroy()
                del users_active[old_admin]
                del user_colors[name]
                set_admin(new_admin)
                ADMIN = new_admin

        # Handle connection errors
        except (ConnectionResetError, Exception) as E:
            #print(E)
            print('Server has disconnected unexpectedly quitting...')
            close_client(1)
            break


def close_client(code: int = 0) -> None:
    """Close the client socket connection and update the chat screen with an appropriate message.

    Args:
        code (int): An optional integer representing the reason for closing the client.
            0 - No specific reason, default code 
            1 - The client was disconnected from the server, either by losing connection, being kicked, or the server disconnecting.
            2 - The client was disconnected from the server due to inactivity.

    Returns:
        None.
    """
    client.close()

    # Display appropriate message on the chat screen based on the code provided
    if code == 1:
        display_message(chat_screen, f'You were disconnected from the server. Client will close in 5 sec...', 'system')
    elif code == 2:
        display_message(chat_screen, f'You were disconnected from the server for inactivity. Client will close in 5 sec...', 'system')

    # Disable all functions and wait for 5 seconds before destroying the GUI
    if code:
        for w in root.winfo_children():
            try:
                w.configure(state="disabled")
            except:
                continue

        time.sleep(5)
    root.destroy()


def send_message(msg: str, client: socket.socket) -> None:
    """
    Send a message to the server.

    Args:
        msg (str): The message to send.
        client (socket.socket): The client socket connected to the server.

    Returns:
        None

    """
    try:
        # Check if the message is empty
        if not msg:
            return
        
        


        if msg.startswith("chat//download"):
            input_value = msg.split("chat//download", 1)[1].strip()

            process = subprocess.Popen(["croc", "--yes"], stdin=subprocess.PIPE)
            stdout, stderr = process.communicate(input=input_value.encode())
            print("---", stdout, "---")           
            return 

        print(msg)

        # Encode the message and send it to the server
        client.send(msg.encode())
        

    # Handle connection errors
    except (ConnectionResetError, Exception) as E:
        print(E)
        print('Server has disconnected unexpectedly quitting...')
        close_client(1)


def display_message(screen: tk.Text, message: str, sender_name: str) -> None:
    """
    Displays a message on the chat screen.

    Args:
        screen (tk.Text): The tkinter text widget to display the chat.
        message (str): The message to display.
        sender_name (str): The name of the user sending the message.

    Returns:
        None
    """
    # Increment the message number
    global message_number
    message_number += 1

    # Generate a timestamp and create a string with the sender name and timestamp
    timestamp = datetime.now().strftime('%H:%M:%S')
    sender_info = f"[{sender_name} - {timestamp}]:"

    # Add a newline to the message 
    message = f" {message}\n"

    # Generate a random color for the sender if they don't already have one
    if sender_name not in user_colors:
        user_colors[sender_name] = generate_random_color(min_brightness=250)

    # Enable the text widget and insert the sender info and message
    screen.configure(state=tk.NORMAL)
    screen.insert(tk.END, sender_info, f"time_and_name{message_number}")
    screen.tag_configure(f"time_and_name{message_number}", font=(
        "Helvetica", 12, "italic"), justify=tk.LEFT, foreground=user_colors[sender_name])
    screen.insert(tk.END, message, f"msg{message_number}")
    screen.tag_configure(f"msg{message_number}", font=(
        "Helvetica", 12), justify=tk.LEFT, foreground=user_colors[sender_name])

    # Disable the text widget to prevent editing
    screen.configure(state=tk.DISABLED)

    # Call the on_chat_text_change function to update the scrollbar
    on_chat_text_change()
    
    
def display_message_client(screen: tk.Text, message: str, sender_name: str) -> None:
    """
    Displays a message on the chat screen. (client only)

    Args:
        screen (tk.Text): The tkinter text widget to display the chat.
        message (str): The message to display.
        sender_name (str): The name of the user sending the message.

    Returns:
        None
    """
    # Increment the message number
    global message_number_client
    message_number_client += 1

    # Generate a timestamp and create a string with the sender name and timestamp
    timestamp = datetime.now().strftime('%H:%M:%S')
    sender_info = f"[{sender_name} - {timestamp}]:"

    # Add a newline to the message 
    message = f" {message}\n"

    # Generate a random color for the sender if they don't already have one
    if sender_name not in user_colors:
        user_colors[sender_name] = generate_random_color(min_brightness=250)

    # Enable the text widget and insert the sender info and message
    screen.configure(state=tk.NORMAL)
    screen.insert(tk.END, sender_info, f"time_and_name_client{message_number_client}")
    screen.tag_configure(f"time_and_name_client{message_number_client}", font=(
        "Helvetica", 12, "italic"), justify=tk.LEFT, foreground=user_colors[sender_name])
    screen.insert(tk.END, message, f"msg_client{message_number_client}")
    screen.tag_configure(f"msg_client{message_number_client}", font=(
        "Helvetica", 12), justify=tk.LEFT, foreground=user_colors[sender_name])

    # Disable the text widget to prevent editing
    screen.configure(state=tk.DISABLED)

    # Call the on_chat_text_change function to update the scrollbar
    on_chat_text_change()
    

def enter_message(client: socket, chat_screen: tk.Text, chat_var: tk.StringVar) -> None:
    """
    Send a message to the server and updates the chat screen with the message.

    Args:
        client (socket.socket): The client socket connected to the server.
        chat_screen (tk.Text): The tkinter text widget to display the chat.
        chat_var (tk.StringVar): The tkinter variable containing the chat message.

    Returns:
        None
    """
    # Get the chat message from the chat entry 
    msg = chat_var.get().strip()

    # Set the name of the user sending the message
    name = f'ADMIN {my_name}' if ADMIN == my_name else my_name

    # If the message is not empty, send it to the server, and update the chat screen with the message 
    if msg:
        send_message(f'chat/{msg}', client)
        display_message_client(chat_screen, msg, name)
        
        # Clear the chat entry from the message 
        chat_var.set("")


def login_session(username_entry : tk.Entry, password_entry : tk.Entry, session_id : int, session_name : str) -> None:
    """
    Logs in the user to the chat room, creates labels for the active user tab and sets the admin 

    Args:
        username_entry (tk.Entry): The tkinter entry widget containing the username of the user.
        password_entry (tk.Entry or str): The tkinter entry widget containing the password of the user or 'NO CODE' if the user does not have a password.
        session_id (int): The session id of the chat room.
        session_name (str): The name of the chat room.

    Returns:
        None
    """
    global my_name
    global ADMIN
    global stop_checking
    global stop_checking_temp
    stop_checking_temp = True
    try:
        # Get the username and password entered by the user
        my_name = username_entry.get().strip()
        if password_entry != 'NO CODE':
            password = password_entry.get().strip()
        else:
            password = 'NO CODE'

        # Send the username and password to the server
        login_message = f'login/name/{my_name}/{session_id}/{password}'
        client.send(login_message.encode())

        # Get the response from the server
        status_code_and_history = client.recv(BUFSIZ)

        # If the user has successfully logged in, show the chat room window
        if status_code_and_history[:6].decode() == 'IN-200':
            print('signed in successfully!')
            stop_checking = True

            # Get the active users from the server
            user_history = pickle.loads(status_code_and_history[6:])
            users_dict = user_history[0]
            admin_name = user_history[1]
            ADMIN = admin_name

            # Display the session information in the chat room
            session_info = f'Room name: {session_name}\nRoom code: {password}'
            session_info = tk.Label(users,
                                    text=session_info,
                                    justify='left',
                                    fg='white', font=("Helvetica", 12),
                                    background=DISCORD_DARK_BLUE,
                                    borderwidth=10,
                                    highlightthickness=5,
                                    highlightbackground="black")
            session_info.pack(pady=5, padx=5)

            # Add each active user to the chat room window
            for name, time_joined in users_dict.items():
                # Create a random color for the user
                user_colors[name] = generate_random_color()

                if name != my_name:
                    font_default = ("Helvetica", 12)
                else:
                    font_default = ("Helvetica", 14, 'bold')

                # Add the user to the list of active users in the chat room
                user = tk.Label(users,
                                text=f'{name} - {time_joined} ',
                                fg=user_colors[name], font=font_default,
                                background=DISCORD_DARK_BLUE)
                user.pack(pady=5)

                users_active[name] = user

            # Set the admin of the chat room
            if ADMIN != 'server_host':
                set_admin(admin_name)

            # Destroy the login window and show the chat room window
            window.destroy()
            root.deiconify()

            # Create a new thread to handle incoming messages from the server
            receive_thread = Thread(target=receive, args=(client, chat_screen))
            receive_thread.daemon = True
            receive_thread.start()

        # If the user has entered an invalid username or password, display an error message
        elif status_code_and_history[:6].decode() == 'IN-400':
            print('user or password were incorrect')
        else:
            print('try again')

        stop_checking_temp = False
    # Handle connection errors 
    except (ConnectionResetError, Exception) as E:
        #print(E)
        print('Server has disconnected unexpectedly quitting...')
        close_client()


def on_keyrelease(event : tk.Event, regex :  str) -> None:
    """
    Changes the color of the text in the widget based on whether it matches the regular expression.

    Args:
        event (Tkinter.Event): The event that triggered the function.
        regex (str): The regular expression to match the text against.

    Returns:
        None
    """
    # get the current text in the entry widget
    current_text = event.widget.get().strip()

    # check if the text matches the regular expression
    if re.match(regex, current_text):
        # set the text color to green
        event.widget.configure(foreground='green')
    else:
        # set the text color to red
        event.widget.configure(foreground='red')


def create_activate_session_window(event : tk.Event) -> None:
    """
    This function is called when the user selects a session from the list of available sessions. 
    It creates a new window for the user to enter their login information, and launches the login process when the 
    user clicks the login button.

    Args:
        event (tk.Event): The event that triggered the function call (the user selecting a session from the list).
    
    Returns:
        None.
    """
    # Get the session ID and name using regex
    selected_index = event.widget.curselection()[0]
    selected_item = event.widget.get(selected_index)
    session_id = re.search(r"session id: (\d+)", selected_item).group(1)
    session_name = re.search(r"name: (\w+)", selected_item).group(1)

    # Create a new window for the login
    login_window = tk.Toplevel(window)
    login_window.resizable(False, False)
    login_window.grab_set()
    login_window.focus_set()

    # Set the title of the window to be "login"
    login_window.title("Login")
    login_window.configure(bg="#1e1e1e")

    # Set the window size and position
    window_width = 225
    window_height = 128 if 'NO CODE' not in selected_item else 100
    screen_width = login_window.winfo_screenwidth()
    screen_height = login_window.winfo_screenheight()
    x = int((screen_width/2) - (window_width/2))
    y = int((screen_height/2) - (window_height/2))
    login_window.geometry(
        "{}x{}+{}+{}".format(window_width, window_height, x, y))

    # Create a style for the window and widgets
    style = ttk.Style(login_window)
    style.theme_use('clam')
    style.configure('.', background='#1e1e1e',
                    foreground='white', font=('Helvetica', 10))
    style.configure('TLabel', padding=6, background='#1e1e1e',
                    foreground='white', font=('Helvetica', 10))
    style.configure('TEntry', padding=6, relief='flat',
                    background='#424242', foreground='white', font=('Helvetica', 10))
    style.configure('TButton', padding=6, relief='flat',
                    background='#424242', foreground='white', font=('Helvetica', 10))
    style.map('TButton', background=[
              ('active', '#606060')], foreground=[('active', 'white')])

    # Create a frame for the login form
    form_frame = ttk.Frame(login_window)
    form_frame.pack(fill='both', expand=True, padx=10, pady=10)

    # Create a label for the name field
    name_label = ttk.Label(form_frame, text="Username:")
    name_label.grid(row=0, column=0, sticky='w')

    # Create an entry field for the name
    name_entry = ttk.Entry(form_frame, foreground='black', validate='key', validatecommand=(
        root.register(lambda text, action: validate_text(12, text, action)), '%P', '%d'))
    name_entry.grid(row=0, column=1)
    name_entry.configure(foreground='red')
    name_entry.bind('<KeyRelease>', lambda e: on_keyrelease(
        e, r'^(?!\d)[a-zA-Z0-9]{3,12}$'))


    # Create a password entry only if the session requires it 
    if 'NO CODE' not in selected_item:
        # Create a label for the password field
        password_label = ttk.Label(form_frame, text="Password:")
        password_label.grid(row=1, column=0, sticky='w')

        # Create an entry field for the password
        password_entry = ttk.Entry(form_frame, foreground='black', validate='key', validatecommand=(
            root.register(lambda text, action: validate_text(5, text, action)), '%P', '%d'))
        password_entry.grid(row=1, column=1)
        password_entry.configure(foreground='red')
        password_entry.bind(
            '<KeyRelease>', lambda e: on_keyrelease(e, r'^[0-9]{5,5}$'))

    # Create a button to submit the login form
    submit_button = ttk.Button(form_frame, text="Login", command=lambda: login_session(
        password_entry=password_entry if 'NO CODE' not in selected_item else 'NO CODE', username_entry=name_entry, session_id=session_id, session_name=session_name))
    submit_button.grid(row=2, column=0, columnspan=2, pady=5)


def validate_text(max_chars: int, text: str, action: str) -> bool:
    """
    Validates text entered by the user in a text entry widget.
    
    Args:
        max_chars (int): The maximum number of characters allowed in the widget.
        text (str): The text entered by the user.
        action (str): The action being performed (inserting or deleting a character).

    Returns:
        bool: True if the action is allowed (text length <= max_chars), False otherwise.
    """
    if action == '0':  # user is deleting a character
        return True
    else:  # user is inserting a character
        return len(text) <= max_chars


def reload_sessions(client : socket.socket, listbox : tk.Listbox) -> None:
    """
    Reloads the sessions list from the server and updates the session listbox.

    Args:
        client (socket.socket): The client socket connected to the server.
        listbox (tk.Listbox): The tkinter listbox that holds the sessions. 

    Returns:
        None.
    """
    global stop_checking_temp
    stop_checking_temp = True
    
    # print message to indicate sessions are being reloaded

    # clear the current session list in the listbox
    listbox.selection_clear(0, tk.END)
    listbox.delete(0, tk.END)

    # request session list from server and receive response
    send_message('reload/sessions', client)
    sessions = pickle.loads(client.recv(BUFSIZ))

    # iterate over the sessions list received from the server and add them to the listbox
    for i, session in enumerate(sessions):
        listbox.insert(tk.END, session)
        listbox.selection_set(i, None)

    stop_checking_temp = False


def on_chat_text_change() -> None:
    """
    Scrolls the chat screen to the bottom to show the latest messages.
    
    Args:
        None.
    
    Returns:
        None.
    """
    chat_screen.yview_moveto(1.0)


def create_session_window() -> None:
    """
    Creates a new window for creating a session with a unique name and password.
    
    Args:
        None.
        
    Returns: 
        None.
    """
    # Create a new window for the login
    session_creation_window = tk.Toplevel(window)
    session_creation_window.resizable(False, False)
    session_creation_window.grab_set()
    session_creation_window.focus_set()

    # Set the title of the window to be "login"
    session_creation_window.title("Create session")
    session_creation_window.configure(bg="#1e1e1e")

    # Set the window size and position
    window_width = 280
    window_height = 160
    screen_width = session_creation_window.winfo_screenwidth()
    screen_height = session_creation_window.winfo_screenheight()
    x = int((screen_width/2) - (window_width/2))
    y = int((screen_height/2) - (window_height/2))
    session_creation_window.geometry("{}x{}+{}+{}".format(window_width, window_height, x, y))

    # Create a style for the window and widgets
    style = ttk.Style(session_creation_window)
    style.theme_use('clam')
    style.configure('.', background='#1e1e1e', foreground='white', font=('Helvetica', 10))
    style.configure('TLabel', padding=6, background='#1e1e1e', foreground='white', font=('Helvetica', 10))
    style.configure('TEntry', padding=6, relief='flat', background='#424242', foreground='white', font=('Helvetica', 10))
    style.configure('TButton', padding=6, relief='flat', background='#424242', foreground='white', font=('Helvetica', 10))
    style.map('TButton', background=[('active', '#606060')], foreground=[('active', 'white')])

    # Create a frame for the login form
    form_frame = ttk.Frame(session_creation_window)
    form_frame.pack(fill='both', expand=True, padx=10, pady=10)

    # Create a label for the name field
    session_name_label = ttk.Label(form_frame, text="Session name:")
    session_name_label.grid(row=0, column=0, sticky='w')

    # Create an entry field for the name
    session_name_entry = ttk.Entry(form_frame, foreground='black', validate='key', validatecommand=(root.register(lambda text, action: validate_text(12, text, action)), '%P', '%d'))
    session_name_entry.grid(row=0, column=1)
    session_name_entry.configure(foreground='red')
    session_name_entry.bind('<KeyRelease>', lambda e: on_keyrelease(e, r'^(?!\d)[a-zA-Z0-9]{3,12}$'))

    # Create a label for the name field
    session_password_label = ttk.Label(form_frame, text="Session password:")
    session_password_label.grid(row=1, column=0, sticky='w')

    # Create an entry field for the name
    session_password_entry = ttk.Entry(form_frame, foreground='black', validate='key', validatecommand=(root.register(lambda text, action: validate_text(5, text, action)), '%P', '%d'))
    session_password_entry.grid(row=1, column=1)
    session_password_entry.configure(foreground='red')
    session_password_entry.bind('<KeyRelease>', lambda e: on_keyrelease(e, r'^[0-9]{5,5}$'))

    # Create a label for the password field
    username_label = ttk.Label(form_frame, text="Username:")
    username_label.grid(row=2, column=0, sticky='w')

    # Create an entry field for the password
    username_entry = ttk.Entry(form_frame, foreground='black', validate='key', validatecommand=(root.register(lambda text, action: validate_text(12, text, action)), '%P', '%d'))
    username_entry.grid(row=2, column=1)
    username_entry.configure(foreground='red')
    username_entry.bind('<KeyRelease>', lambda e: on_keyrelease(e, r'^(?!\d)[a-zA-Z0-9]{3,12}$'))

    # Create a button to submit the login form
    submit_button = ttk.Button(form_frame, text="Create", command=lambda: login_create(username_entry, session_name_entry, session_password_entry))
    submit_button.grid(row=3, column=0, columnspan=2, pady=5)


def login_create(username_entry : tk.Entry, session_name_label : tk.Entry, session_password_entry : tk.Entry) -> None:
    """
    Logs in the user and creates a session on the server.

    Args:
        username_entry (tk.Entry): The tkinter entry widget containing the username of the user.
        session_name_label (tkinter.Label): The tkinter entry widget containing the session name.
        session_password_entry (tkinter.Entry): The tkinter entry widget containing the session password. 

    Returns:
        None
    """
    # Declare global variables to be used within this function
    global my_name
    global ADMIN
    global stop_checking
    global stop_checking_temp
    stop_checking_temp = True

    try:
        # Get user inputs for the session and user name
        my_name = username_entry.get().strip()
        session_name = session_name_label.get().strip()
        session_password = session_password_entry.get().strip()

        # If no password was given, set the password to "NO CODE"
        if session_password == '':
            session_password = 'NO CODE'

        # Create the message to send to the server to create the session
        create_message = f'create/{session_name}/name/{my_name}/{session_password}'

        # Send the create session message to the server
        client.send(create_message.encode())

        # Receive response from the server
        status_code_and_history = client.recv(BUFSIZ)

        # If the server responds with a successful status code, continue
        if status_code_and_history[:6].decode() == 'IN-200':
            stop_checking = True

            # Get a dictionary of active users in the session
            users_dict = pickle.loads(status_code_and_history[6:])

            # Create a label to display the session information
            session_info = f'Room name: {session_name}\nRoom code: {session_password}'
            session_info = tk.Label(users,
                                    text=session_info,
                                    justify='left',
                                    fg='white', font=("Helvetica", 12),
                                    background=DISCORD_DARK_BLUE,
                                    borderwidth=10,
                                    highlightthickness=5,
                                    highlightbackground="black")
            session_info.pack(pady=5, padx=5)

            # For each user in the session, create a label to display their name
            for name, time_joined in users_dict.items():
                # Create a user color
                user_colors[name] = generate_random_color()

                # Add user to active users tab
                user = tk.Label(users,
                                text=f'{name} - {time_joined} ',
                                fg=user_colors[name], font=(
                                    "Helvetica", 14, 'bold'),
                                background=DISCORD_DARK_BLUE)
                user.pack(pady=5)

                users_active[name] = user

            # Set the current user as the admin and update the global ADMIN variable
            set_admin(my_name)
            ADMIN = my_name

            # Destroy the password and login TOP and show the main chat screen
            window.destroy()
            root.deiconify()

            # Create a receive thread that will handle received messages
            receive_thread = Thread(target=receive, args=(client, chat_screen))
            receive_thread.daemon = True
            receive_thread.start()

        # If the server responds with an error status code, display an error message
        elif status_code_and_history[:6].decode() == 'IN-400':
            print('user or password were incorrect')
        else:
            print('try again')

        stop_checking_temp = False
    # Handle connection errors 
    except (ConnectionResetError, Exception) as E:
        #print(E)
        print('Server has disconnected unexpectedly quitting...')
        close_client()


def setup_root() -> tk.Tk:
    """
    Set up the root window for the chat room application.

    Args: 
        None.
        
    Returns:
        tk.Tk: The window of the chat room application.
    """
    # Setup the global variables 
    global users 
    global chat_screen
    global root 
    
    # Initiate root and hide it
    root = tk.Tk()
    root.withdraw()

    # Define window dimensions and position
    window_width, window_height = 1050, 500
    root.minsize(width=500, height=250)
    screen_width, screen_height = root.winfo_screenwidth(), root.winfo_screenheight()
    x, y = int((screen_width/2) - (window_width/2)), int((screen_height/2) - (window_height/2))
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")
    Grid.columnconfigure(root, tuple(range(1)), weight=1, minsize=20)
    Grid.rowconfigure(root, tuple(range(1)), weight=1)

    # Set window title and background color
    root.title('chat room')
    root.config(background=DISCORD_DARK_BLUE)

    # Define font size and style
    fontsize = font.Font(size=10, weight='bold', name='Cascadia code')

    # Create chat text variable and entry widget
    chat_var = tk.StringVar()
    chat_var.set('')
    chat_entry = tk.Entry(root, fg='white', font=("Helvetica", 12), textvariable=chat_var,
                          width=100, background=DISCORD_DARK_BLUE, disabledbackground=DISCORD_DARK_BLUE,
                          borderwidth=3, insertbackground='white')
    chat_entry.grid(row=1, column=0, sticky='ew', ipady=5, padx=4)
    chat_entry.bind('<Return>', lambda x: enter_message(client, chat_screen, chat_var))
    chat_entry.config(insertontime=500, insertofftime=500)  # configure the widget to flash the insertion cursor


    def upload_file(): 
        def send_file(file_path):
            
            # Run the croc command to send the file and capture the output
            os.environ["CROC_SECRET"] = file_path.split("/")[-1].strip()
            result = subprocess.run(
                ['croc', 'send', file_path],
                text=True,
                env = os.environ, 
            )

            print("dwaadwwwwwwwwww-------")
        
        file_path = fd.askopenfilename() # filedialog.askopenfilename()
        if file_path: 
            send_message(f"chat//file code {file_path.split('/')[-1].strip()}", client)
            thread_file = threading.Thread(target=send_file, args=(file_path, ))
            thread_file.daemon = True
            thread_file.start() 
            
            

    file_button = tk.Button(root, text="upload\n file", command=lambda: upload_file())
    file_button.grid(row=1, column=1, sticky='ew', ipady=5, padx=4)

    # Create chat screen and scrollbar widgets
    chat_screen = tk.Text(root, font=fontsize, state='disabled', width=100, borderwidth=3,
                           background=DISCORD_DARK_BLUE, wrap="word", spacing1=5)
    chat_screen.grid(row=0, column=0, sticky='nsew', padx=4)
    scrollb = tk.Scrollbar(root, troughcolor=DISCORD_DARK_BLUE, background='gray', borderwidth=3,
                           command=chat_screen.yview)
    scrollb.grid(row=0, column=2, rowspan=2, sticky=tk.NS)
    chat_screen['yscrollcommand'] = scrollb.set

    # Create label and frame widgets for active users
    active_users = tk.Label(root, width=15, borderwidth=20, background='black', font=("Helvetica", 12),
                            text='active users', foreground='white')
    active_users.grid(row=1, column=3, sticky='ews')
    users = tk.Frame(root, width=15, borderwidth=3, background=DISCORD_DARK_BLUE)
    users.grid(row=0, column=3, sticky='nsew')

    return root


def create_session_list_window(root: tk.Tk, client: socket.socket) -> tk.Toplevel:
    """
    Create a tkinter window to display a list of sessions.

    Args:
        root (tk.Tk): The window of the chat room application.
        client (socket.socket): A client socket connected to the server.

    Returns:
        tk.Toplevel: a tkinter window of the list of sessions
    """
    # Create a new window
    window = tk.Toplevel(root)
    window.title("Session List")
    window.configure(bg="#1e1e1e")

    # Set the window size and position
    window_width = 790
    window_height = 340
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = int((screen_width / 2) - (window_width / 2)) - 100
    y = int((screen_height / 2) - (window_height / 2))
    window.geometry("{}x{}+{}+{}".format(window_width, window_height, x, y))
    window.minsize(300, 335)
    window.maxsize(None, 1000)

    # Create a style for the window and widgets
    style = ttk.Style(window)
    style.theme_use('clam')
    style.configure('.', background='#1e1e1e',
                    foreground='white', font=('Helvetica', 10))
    style.configure('TButton', padding=6, relief='flat',
                    background='#424242', foreground='white', font=('Helvetica', 10))
    style.configure('TLabel', padding=6, background='#1e1e1e', foreground='white', font=('Helvetica', 10))
    style.configure('TEntry', padding=6, relief='flat', background='#424242', foreground='white', font=('Helvetica', 10))
    style.map('TButton', background=[
              ('active', '#606060')], foreground=[('active', 'white')])

    # Create a frame for the listbox and scrollbar
    frame = ttk.Frame(window)
    frame.pack(fill='both', expand=True, padx=10, pady=10)

    # Create a listbox to display the sessions
    listbox = tk.Listbox(frame, bg='#2b2b2b', fg='white', font=('Helvetica', 11),
                         selectmode='browse', highlightthickness=0, activestyle="none",
                         takefocus=False, selectbackground='#3f3f3f', selectforeground='white')
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    listbox.bind("<Double-Button-1>", lambda event: create_activate_session_window(event))
    reload_sessions(client, listbox)

    # Create a scrollbar for the listbox
    scrollbar = tk.Scrollbar(frame, bg='#1e1e1e', activebackground='#1e1e1e',
                             troughcolor='#2b2b2b', command=listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    listbox.config(yscrollcommand=scrollbar.set)

    # Create a frame for the buttons
    button_frame = ttk.Frame(window)
    button_frame.pack(pady=10)

    # Create a Reload button to reload the session list
    reload_button = ttk.Button(button_frame, text="Reload",
                               command=lambda: reload_sessions(client, listbox))
    reload_button.pack(side=tk.LEFT, anchor=tk.W, padx=5)

    # Create a Create Session button to create a new session
    create_button = ttk.Button(
        button_frame, text="Create Session", command=create_session_window)
    create_button.pack(side=tk.LEFT, padx=5, anchor=tk.W)

    # Create a frame for the close server label, entry, and check mark
    close_server_frame = ttk.Frame(window)
    close_server_frame.pack(side=tk.BOTTOM, pady=10)

    # Create a label for the close server field 
    close_server_label = ttk.Label(close_server_frame, text="EXIT code: ")
    close_server_label.pack(side=tk.LEFT, anchor=tk.S,pady=10, padx=5)

    # Create an Entry for the close server field
    close_server_entry = ttk.Entry(close_server_frame, foreground='black',width=18,  validate='key', validatecommand=(root.register(lambda text, action: validate_text(5, text, action)), '%P', '%d'))
    close_server_entry.pack(side=tk.LEFT, anchor=tk.S, padx=5,pady=10)
    close_server_entry.configure(foreground='red')
    close_server_entry.bind('<KeyRelease>', lambda e: on_keyrelease(e, r'^[0-9]{5,5}$'))

    # Load the image and convert it to a format that Tkinter can use
    image_file = "check_mark.png"
    image = Image.open(image_file)
    image = image.resize((15, 15))
    check_mark_photo = ImageTk.PhotoImage(image)

    # Create a check mark button to close the server
    check_mark = ttk.Button(
        close_server_frame, text='s',image=check_mark_photo,compound='none',width=3, command=lambda: close_server(client, close_server_entry))
    check_mark.image = check_mark_photo
    check_mark.pack(side=tk.RIGHT, anchor=tk.CENTER, padx=5)

    # Load the image and convert it to a format that Tkinter can use
    image_file = "question_mark.png"
    image = Image.open(image_file)
    image = image.resize((15, 15))
    question_mark_photo = ImageTk.PhotoImage(image)
 
    # Create a help button to open a help screen 
    help_button = ttk.Button(
        button_frame, image=question_mark_photo,command=lambda: create_help_window())
    help_button.image = question_mark_photo
    help_button.pack(side=tk.LEFT, anchor=tk.W, padx=5)

    return window


def close_server(client: socket.socket, close_server_entry: tk.Entry) -> None:
    """
    Send a message to the server to request it to close the connection.
    If the server responds with a successful status code, close the GUI window.

    Args:
        client (socket.socket): The client socket connected to the server.
        close_server_entry (tk.Entry): The entry widget containing the server address.

    Returns:
        None.
    """

    try:
        # Create the message to send to the server to close it
        close_message = f'close/{close_server_entry.get().strip()}'
        close_server_entry.delete(0, tk.END)

        # Send the close message to the server
        client.send(close_message.encode())

        # Receive a response from the server
        data = client.recv(BUFSIZ)

        # If the server responds with a successful status code, continue
        if data.decode() == 'IN-200':
            # Close the GUI window
            root.destroy()
        # If the server responds with an error status code, display an error message
        elif data[:6].decode() == 'IN-400':
            print('User or password were incorrect')
        else:
            print('Try again')

    # Handle connection errors
    except (ConnectionResetError, Exception) as e:
        print(e)
        print('Server has disconnected unexpectedly. Quitting...')
        close_client()


def create_help_window() -> None: 
    """
    Creates a new window for user help.
    
    Args:
        None.
        
    Returns: 
        None.
    """
    # Create a new window for the login
    help_window = tk.Toplevel(window)
    #help_window.resizable(False, False)
    help_window.grab_set()
    help_window.focus_set()

    # Set the title of the window to be "login"
    help_window.title("help")
    help_window.configure(bg="#1e1e1e")

    # Set the window size and position
    window_width = 635
    window_height = 385
    screen_width = help_window.winfo_screenwidth()
    screen_height = help_window.winfo_screenheight()
    x = int((screen_width/2) - (window_width/2))
    y = int((screen_height/2) - (window_height/2))
    help_window.geometry("{}x{}+{}+{}".format(window_width, window_height, x, y))
    help_window.resizable(False,False)
    
    # Create a style for the window and widgets
    style = ttk.Style(help_window)
    style.theme_use('clam')
    style.configure('.', background='#1e1e1e', foreground='white', font=('Helvetica', 10))
    style.configure('TLabel', padding=6, background='#1e1e1e', foreground='white', font=('Helvetica', 10))
    style.configure('TEntry', padding=6, relief='flat', background='#424242', foreground='white', font=('Helvetica', 10))
    style.configure('TButton', padding=6, relief='flat', background='#424242', foreground='white', font=('Helvetica', 10))
    style.map('TButton', background=[('active', '#606060')], foreground=[('active', 'white')])

    # Create a frame for the login form
    form_frame = ttk.Frame(help_window)
    form_frame.pack(fill='both', expand=True, padx=10, pady=10)

    help_text = '''
    welcome to my chat client!
    
    You may choose between the avaliable sessions, or create a session for yourself.
    If you choose to join a session, you need to know the code of it before joining.
    Another option is to join a session without a code, sessions without a code are marked 'NO CODE'.
    When entering a session you will be required to enter your username and code if needed. 
    To enter a session double click on the session you would like to join
    When creating a session you will be required to create a session name, code, and add your username. 
    Leaving the password entry empty will create a session with no code.
    EXIT code is meant for closing the server if you are provided with the server exit code. 
    The code is only available to people who have access to the server.
    users who are inactive will be disconnected after 4 min, ADMIN can not be disconnected.
    
    username - consistes of 3 to 12 characters, can't start with a digit
    session name -  consistes of 3 to 12 characters, can't start with a digit
    password - a 5 digit code, no alphabet characters 
    
    '''
    
    # Create a label for the password field
    help_label = ttk.Label(form_frame, text=help_text)
    help_label.grid(row=0, column=0, sticky='w')

 

    # Create a button to submit the login form
    submit_button = ttk.Button(form_frame, text="back", command=lambda: help_window.destroy())
    submit_button.grid(row=1, column=0, columnspan=2, pady=5)    


def check_server_connection(client: socket.socket) -> None:
    '''
    Checks server connectivity by sending a message every 1 second, if it doesn't answer disconnect.
    
    Args:
        client (socket.socket): Client socket connected to the server.
    
    Returns:
        None.
    '''
    while True:
        try:
            # if logged in don't check anymore 
            if stop_checking:
                break
            
            if not stop_checking_temp:
                # Send a test message to the server to check if it's still responsive
                client.send('check_connectivity'.encode())
            
            # Sleep 1 second 
            time.sleep(1)

            

            
        # Handle connection errors 
        except (ConnectionResetError, Exception) as E:
            #print(E)
            print('Server has disconnected quitting...')
            close_client()

def on_toplevel_close() -> None:
    '''
    Destroy root if window is closed by the user before joing a session
    
    Args:
        None.
        
    Returns:
        None.
    
    '''
    if window.wm_protocol("WM_DELETE_WINDOW"):
        root.destroy()



class Client: 
    def __init__(self) -> None:
        # Create a client socket and connect to the server
        self.finder = ServerFinder(HOST_IP, get_open_port())
        self.root = setup_root()

    def run(self):
        global window 
        global client 

        self.client = self.finder.connect()
        client = self.client

        # Create root and session list window
        self.window = create_session_list_window(self.root, self.client)
        self.window.protocol("WM_DELETE_WINDOW", on_toplevel_close)
        window = self.window 

        # Create a new thread to check connectivity 
        self.check_server_connection_thread = Thread(target=check_server_connection, args=(self.client,))
        self.check_server_connection_thread.daemon = True
        self.check_server_connection_thread.start()
        
        # Start the main loop 
        self.root.mainloop()

def create_client(): 
    return Client()