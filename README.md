# Secure-FTP-Server
Final project for Applied Cryptography

## How to Use
1. Run the Network
- `python3 network.py`
- flags (All args are optional.)
  - -n [path]: specifies the path to the network directory
  
2. Run the Server
- `python3 server.py [flags]`
- flags: (All args are optional. Note that if -s serverRSA is left to default, it will first check the specified server directory, and if it cannot find the keys there will default to those in the src/example_server_keys directory.)
  - -s [path]: specifies the path to the server folder
  - -n [path]: specifies the path to the network directory
  - -r [path]: specifies the path to the directory containing the server RSA keys
  
3. Run the Client
- `python3 client.py [flags]`
- flags (All args are optional unless you are a new user and must use -N. Note that if -s serverRSA is left to default, the server public RSA key must be in the client    directory.)
  - -u: specifies that you are creating a new user folder on the server
  - -c [path]: specifies the directory of the client, this is where you can select files to upload and where files will be downloaded
  - -n [path]: specifies the network path, must be the same as the network path of the server
  - -r [path]: specifies the path/location of the server public RSA key, if left empty it will expect a file with the RSA key named serverRSApublic.pem to be located within the client directory

4. When prompted, enter your username and password if you are a returning user. If you are a new user enter a username and a password of your choice. 

5. Once the server responds with "Session established.", you may interact with the server normally using any of the commands below. 

## Client Commands
Command structure: cmd [args]
|Command|Description|Arguments|
|---|---|---|
|MKD|Creates a directory in the server-side working directory of the user|[Directory Name]|
|RMD|Deletes a directory in the server-side working directory if it exists|[Directory Name]|
|GWD|Returns the server working directory|None|
|LST|Lists the contents of the server working directory|None|
|UPL|Uploads an encrypted version of a file from the client-side directory|[File Name]|
|DNL|Downloads and decrypts a file from the server to the client-side directory|[File Name]|
|RMF|Deletes a file on the server-side working directory|[File Name]|
|end_session|Cleanly exits a session|None|

## Encryption Specifications
* Files are encrypted using AES in GCM mode and a password based key derived from scrypt using the password that the client enters as their file encryption/decryption password
* Messages are encrypted using AES in GCM mode and a key created by the client a the beginning of each session

**Key establishment protocol:** 
1. Client generates a session key of 16 random bytes
2. This key is then encrypted with RSA using the server's public key
3. The encrypted session key and initial nonce is sent to the server in a hybrid message with the random bytes that will be used to generate the nonce for each cipher and the login message in the form loginType:username:password
4. Server responds with the client's username encrypted by the session key in AES

**Client authentication:**
1. When the server recieves the initial message from the client containing the session key, username, password, etc. outlined in the diagram it will check if the loginType is newusr. If it is and there is no other user with the same username, the server creates a new user folder in the server directory named by the username. Inside the folder, the server will create a new file containing the user's password hashed with SHA256 and a root folder, with which the user will interact. Note: the user only has access to the files and directories that are below the root directory and cannot see their hashed password file.
2. If the message loginType is login, the server will hash the password given and check against the hashed password file stored in the user's folder. The server authenticates the client by confirming the two hashes are equal. 
3. The server confirms authentication by sending the client their username encrypted in AES with the session key and nonce generated from the random bytes sent by the client.

![Session Establishment Diagram](diagrams/a.png)


**Protocol for commands:**
* When the client enters a command, the command, arguments and payload are sent over encrypted with AES using the session key and an incremented nonce. 
* Ex: Client command in the format: 'mkd \<directory name\>' will be encrypted as 'mkd \<directory name\>' and sent to the server 
  
![Command Diagram](diagrams/b.png)


**Storing sensitive data:**
* Hashed client passwords are stored on the server side in the user's folder (user does not have access to)
* Server stores its public key in a plaintext file
* Server stores its private key in a file encrypted with AES in GCM mode using a key derived from the password
* The client's files are stored on the server side in the user's directory encrypted using AES with a password derived key that only the client ever uses or sees
