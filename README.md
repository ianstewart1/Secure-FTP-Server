# Secure-FTP-Server
Final project for Applied Cryptography


## How To Setup

## How to Use
1. Run the Network
2. Run the Server
3. Run the Client
### Flags:
- -n: creates a new user

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

## Crypto Stuff
- Files are encrypted using AES in GCM mode and a key derived from scrypt
- messages are encrypted using AES in GCM mode and a key created by the client a the beginning of each session
