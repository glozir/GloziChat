# Chat Room App
This RFC describes a chat room app that allows users to join existing sessions or create new ones. Each session has an admin who can use multiple commands and kick users. The app is written in Python and uses Tkinter for the GUI.

## Features

### Session Management
Users can join an existing session by entering the session code or join a session without a code (marked "NO CODE"). When joining a session, users must enter a username that consists of 3 to 12 characters and cannot start with a digit. Users can also create their own session by entering a session name that consists of 3 to 12 characters and cannot start with a digit. When creating a session, users can optionally set a 5-digit password that consists of only numerical characters. Sessions with a password require users to enter the correct password to join.

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
The app includes a server exit code that allows users with access to the server to close it. The exit code is displayed on the server side and can be used from the client side by entering the correct code after using the /close command. The server exit code is only available to users who have access to the server.

### User Interface
The app uses the Tkinter GUI library to provide a user-friendly interface for creating and joining chat sessions. Users can see a list of available sessions and join them by entering the session code or create their own session by entering a session name and, optionally, a password. Within a chat session, users can send messages, see other users' messages, and use the available commands.

### Connection Process
The app's connection process allows for the creation and joining of chat sessions without prior knowledge of the server or other users. The client sends a ping broadcast packet within the local area network, and the server sniffs the packet and extracts the host and port values. Meanwhile, the client sets up a UDP socket using the host and port values it provided to the server. The server sends back a message containing its own IP address and port number to the UDP socket that the client just set up. This message contains the necessary information for the client to establish a TCP connection with the server.

### Security Considerations
The app includes a password feature that provides an additional layer of security for sessions.

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


### Conclusion
The chat room app provides users with a secure and flexible way to communicate with each other. Its use of Python and Tkinter ensures a stable and user-friendly experience, and its added features of admin privileges and the ability to close the server from the client side further enhance the app's functionality and convenience.




