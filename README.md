# Chat Room App
This chat room app is a Python application that provides a flexible and secure way for users to communicate with each other. Each session has an admin who can use multiple commands and kick users. The app is written in Python and uses Tkinter for the GUI to ensure a stable and user-friendly experience.

## Features

### Session Management
Users can join an existing session by entering the session code or join a session without a code (marked "NO CODE"). 
When joining a session that requires a password, users must enter the correct 5-digit password to join. When joining a session, users must enter a username that consists of 3 to 12 characters and cannot start with a digit. Users can also create their own session by entering a session name that consists of 3 to 12 characters and cannot start with a digit. When creating a session, users can optionally set a 5-digit password that consists of only numerical characters. Sessions with a password require users to enter the correct password to join.

### User Commands
The app includes several commands that users can use within chat sessions, including:

  - /help: displays the available commands
  - /quote: returns a random quote
  - /time: returns the current server time
  - /echo [text]: echoes the provided text back to the user
  - /kick [member]: kicks the specified member from the session (admin-only)
  - /quit: disconnects the user from the session
  - /close: closes the session (admin-only)

### Admin Privileges
Admins have additional privileges within chat sessions. They cannot be timed out for inactivity and have the ability to use the /kick and /close commands.

### Inactivity Timeout
The app includes a 4-minute inactivity timeout that disconnects users who have not sent any messages for the duration of the timeout. Admins are exempt from this timeout.

### Server Exit Code
The app includes a server exit code that allows users with access to the server to close it. The exit code is displayed on the server side (stdout) and can be used from the client side by entering the correct code in the sessions window, after entering it the server will disconnect all clients and close itself. 
The server exit code is only available to users who have access to the server.

![image](https://user-images.githubusercontent.com/93617974/229585623-2e07fff2-f083-4d13-93b6-061a86a264d2.png)

### Connection Process
The app's connection process allows for the creation and joining of chat sessions without prior knowledge of the server or other users. The client sends a ping broadcast packet within the local area network, and the server sniffs the packet and extracts the host and port values. Meanwhile, the client sets up a UDP socket using the host and port values it provided to the server. The server sends back a message containing its own IP address and port number to the UDP socket that the client just set up. This message contains the necessary information for the client to establish a TCP connection with the server.

### Security Considerations
The app includes a password feature that provides an additional layer of security for sessions.

### Graphics and User Interface 

The chat room app features a graphical user interface (GUI) that provides an easy-to-use platform for users to communicate with each other. The chat graphics window displays the chat messages and the list of active users in the session. In addition, it displays the name and code of the current session in the top corner of the window.

![image](https://user-images.githubusercontent.com/93617974/229588148-5de98b67-b4c9-4e48-bef9-947489ad2f5a.png)


![image](https://user-images.githubusercontent.com/93617974/229588318-c27a643c-769f-4f4c-b08f-f136378375ad.png)

The session list window lists all available sessions and includes information about each session, such as the number of active users, the creation time, the creator's username, and whether a password is required to join. This window also features three buttons, one for reloading the session list, one for creating a new session, and the third for displaying general information about the app, represented by a question mark icon.

Moreover, the session list window enables users to enter the server exit code, which allows authorized users to close the server.

![image](https://user-images.githubusercontent.com/93617974/229581678-52a163ff-1b08-4bad-9287-952f25d92288.png)


### Usage

To use the chat room app, follow these steps:

  1. Ensure that Python and the required libraries are installed on your machine.
  2. Download the client.py, utils.py, server.py, question_mark.png and check_mark.png files.
  3. Open a command prompt or terminal and navigate to the directory where the files are located.
  4. Run the server.py file by typing "python server.py" and pressing enter.
  5. Open a new terminal window or run the client.py file on a different computer.
  6. Run the client.py file by typing "python client.py" and pressing enter.
  7. join an existing session or create a new session (to join a session double click on it).
  8. Begin communicating with other users within the session.

  Note: If you want to run multiple clients on the same machine, each client must be run in a separate terminal window.

### Requirements
The app requires Python and the following libraries:

  - datetime
  - time
  - re
  - pickle
  - json
  - select
  - scapy
  - socket
  - threading
  - tkinter
  - PIL

Additionally, the app requires the following files:

  - client.py: the client-side code for the chat room app
  - utils.py: a utility module used by both the client and server
  - server.py: the server-side code for the chat room app
  - question_mark.png : a picture used for a button in the session list window
  - check_mark.png : a picture used for a button in the session list window 

### Conclusion
The chat room app provides users with a secure and flexible way to communicate with each other. Its use of Python and Tkinter ensures a stable and user-friendly experience, and its added features of admin privileges and the ability to close the server from the client side further enhance the app's functionality and convenience.




