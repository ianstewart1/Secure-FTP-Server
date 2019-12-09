# Secure-FTP-Server
Final project for Applied Cryptography


## How To Setup

## How to Use
1. Run the Network
- `python3 network.py`
2. Run the Server
- `python3 server.py [flags]`
- flags:
  - s [path]: specifies the path to the server folder
  
3. Run the Client
- `python3 client.py [flags]`
- flags
  - -N: specifies that you are creating a new user folder on the server
  - -n [path]: specifies the network path, must be the same as the network path of the server
  - -c [path]: specifies the directory of the client, this is where you can select files to upload and where files will be downloaded
  - -s [path]: specifies the path/location of the server public RSA key, if left empty it will expect a file with the RSA key named serverRSApublic.pem to be located within the client directory

## Client Commands
|Command|Description|Arguments|
|---|---|---|
|MKD|   |   |
|RMD|   |   |
|GWD|   |   |
|LST|   |   |
|UPL|   |   |
|DNL|   |   |
|RMF|   |   |

## Encryption Specifications
* Files are encrypted using AES in GCM mode and a key derived from scrypt
* Messages are encrypted using AES in GCM mode and a key created by the client a the beginning of each session

**Key establishment protocol:** 
1. Client generates a session key of 16 random bytes
2. This key is then encrypted with RSA using the server's public key
3. The encrypted session key is sent to the server in a hybrid message with the random bytes that will be used to generate the nonce for each cipher and the login message in the form loginType:username:password
4. Server responds with the client's username encrypted by the session key in AES

**Client authentication:**
1. When the server recieves the initial message from the client containing the session key, username, password, etc. outlined in the diagram it will check if the new user flag -N is present. If it is, the server creates a new user folder named by the username. Inside the folder, the server will create a new file containing the user's password hashed by SHA256 and the folder the user will interact with. Note: the user only has access to the subfolder and cannot see their password file.
2. If the message does not contain the -N flag, the server will hash the password given and check against the hashed password file stored in the user's folder. The server authenticates the client by confirming the two hashes are equal. 
3. The server confirms authentication by sending the client their username encrypted in AES with the session key and nonce generated from the random bytes sent by the client.

![Session Establishment Diagram](diagrams/a.png)


**Protocol for commands:**
* When the client enters a command, the command, arguments and payload are sent over encrypted with AES using the session key and incremented nonce. 
* Ex: Client command in the format: 'mkd \<directory name\>' will be encrypted as 'mkd \<directory name\>' and sent to the server 
  
![Command Diagram](diagrams/b.png)


**Storing sensitive data:**
* Hashed client passwords are stored on the server side in the user's folder (user does not have access to)
* Server stores its public key in a plaintext file
* Server stores its private key in a file encrypted with AES in GCM mode using its password
* Client stores the Server's public RSA key in the client directory
