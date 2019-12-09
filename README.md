# Secure-FTP-Server
Final project for Applied Cryptography


## How To Setup

## How to Use
1. Run the Network
2. Run the Server
3. Run the Client
### Flags:
- -N: creates a new user

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
- Files are encrypted using AES in GCM mode and a key derived from scrypt
- messages are encrypted using AES in GCM mode and a key created by the client a the beginning of each session

**Key establishment protocol:** 
1. Client generates a session key of 16 random bytes
2. This key is then encrypted with RSA using the server's public key
3. The encrypted session key is sent to the server in a hybrid message with the random bytes that will be used to generate the nonce for each cipher and the login message in the form loginType:username:password
4. Server responds with the client's username encrypted by the session key in AES

**Client authentication:**
1. When the server recieves the initial message from the client containing the session key, username, password, etc. outlined in the diagram it will check if the new user flag -N is present. If it is, the server creates a new user folder named by the username. Inside the folder, the server will create a new file containing the user's password hashed by SHA256 and the folder the user will interact with. Note: the user only has access to the subfolder and cannot see their password file.
2. If the message does not contain the -N flag, the server will hash the password given and check against the hashed password file stored in the user's folder. The server authenticates the client by confirming the two hashes are equal. 
3. The server confirms authentication by sending the client their username encrypted in AES with the session key and nonce generated from the random bytes sent by the client

**Diagram of session establishment**

client              server
|                     |
|                     |
|  message stuff cool |
-----------------------
|                     |
|                     |


how your main protocol for transferring commands and files are implemented: 
Message from client to server encrypted w AES in GCM mode

how you store sensitive data like passwords and private keys on the server and the client (whatever applies): 
Store passwords hashed in a file in the user's folder
- user cannot see the file 
Server stores its own public and private key in a file encrypted with AES GCM mode using its password 
Client stores the Server's public RSA key 
