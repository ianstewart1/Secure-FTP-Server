import os
import getopt
import time
import getpass
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from netinterface import network_interface
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes


class Server:

    ## INITIALIZATION
    
    def __init__(self, server, network, serverRSA):
        if server == None:
            server = os.getcwd().split('src')[0] + 'server'
            if not os.path.exists(server):
                os.mkdir(server)
        self.serverAddress = server
        if not os.path.exists(self.serverAddress + "/USERS"):
            os.mkdir(self.serverAddress + "/USERS")
        # password to protect private rsa
        self.password = getpass.getpass("Enter RSA password: ")
        if serverRSA == None:
            serverRSA = self.serverAddress + '/serverRSApublic.pem'
        if not os.path.exists(serverRSA):
            serverRSA = os.getcwd() + "/example_server_keys/serverRSApublic.pem"
        with open(serverRSA, 'rb') as f:
            self.serverRSApublic = RSA.import_key(f.read())
        serverPrivate = self.serverAddress + '/serverRSAprivate.pem'
        if not os.path.exists(serverPrivate):
            serverPrivate = os.getcwd() + "/example_server_keys/serverRSAprivate.pem"
        self.getPrivateKey(serverPrivate)

        self.workingDir = None
        self.currentUser = None
        self.lastMsg = 0
        self.msgNonce = None
        self.AESKey = None
        # network connection
        if network == None:
            network = os.getcwd().split('src')[0] + 'network'
            if not os.path.exists(network):
                os.mkdir(network)
        self.networkPath = network
        self.networkRef = network_interface(self.networkPath, 'server')
        self.sessions = {}
        print("Server Running")

    def initSession(self, resp='', src=''):
        print("initializing session")
        # wait for client message
        if resp == '' and src == '':
            resp, src = self.readMsg()

        decryptRSAcipher = PKCS1_OAEP.new(self.serverRSAprivate)
        sizeOfKey = self.serverRSApublic.size_in_bytes()

        # Parse out and decrypt session key and random bytes
        encAESandRandom = resp[:sizeOfKey] 
        AESandRandom = decryptRSAcipher.decrypt(encAESandRandom)
        self.AESKey = AESandRandom[:16]
        zero = 0
        self.msgNonce = AESandRandom[16:] + zero.to_bytes(8, 'big')

        # Get message content
        resp = self.processResp(resp[sizeOfKey:])

        # Authenticate user
        auth_type, username, password = resp.split(":".encode("utf-8"), 3)
        h = SHA256.new(data=password)
        password = h.digest()
        if auth_type.decode('utf-8') == "newusr":
            self.createNewUser(username.decode('utf-8'), password)
        if (not self.authUser(username.decode('utf-8'), password)):
            print('Nice try hacker man, get outta here!')
            self.writeMsg(self.encMsg("end_session"), username.decode('utf-8'))
            time.sleep(.2)
            self.initSession()
            return False

        self.currentUser = username.decode('utf-8')
        self.workingDir = '/root'

        # Create response if login was successful
        serverResponse = self.encMsg(self.currentUser)
        self.writeMsg(serverResponse)

        self.sessions[self.currentUser] = Session(self.currentUser, self.AESKey, self.msgNonce, self.workingDir, self.lastMsg, self.networkRef)

        

    def createNewUser(self, username, passHash):
        userfolder = self.serverAddress + "/USERS/" + username
        if os.path.exists(userfolder):
            self.writeMsg(self.encMsg("Invalid username"), username)
            self.writeMsg(self.encMsg("end_session"), username)
        else:
            os.mkdir(userfolder)
            os.mkdir(userfolder + "/root")
            with open(userfolder + "/.hash_check.hash", "wb") as f:
                f.write(passHash)


    def authUser(self, username, passHash):
        if username in os.listdir(self.serverAddress + '/USERS'):
            with open(self.serverAddress + '/USERS/' + username + '/.hash_check.hash', 'rb') as f:
                if passHash == f.read():
                    return True
        return False

    def encMsg(self, message, data=b''):
        if isinstance(message, str):
            message = message.encode('utf-8')
        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM, self.msgNonce)
        if(data != b''):
            cipher_text, tag = cipher_aes.encrypt_and_digest(
                message + " ".encode('utf-8') + data)
        else:
            cipher_text, tag = cipher_aes.encrypt_and_digest(message)
        self.incNonce()
        return tag + cipher_text

    def processResp(self, resp):
        tag = resp[:16]
        ciphertext = resp[16:]
        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM, self.msgNonce)
        self.incNonce()
        try:
            plain = cipher_aes.decrypt_and_verify(ciphertext, tag)
            return plain
        except ValueError:
            print('MAC verification failed, ending session...')
            exit(1)

    def writeMsg(self, msg, dst = ''):
        if(dst == ''):
            dst = self.currentUser
        self.networkRef.send_msg(dst, msg)

    def readMsg(self):
        return self.networkRef.receive_msg()

    def incNonce(self):
        self.msgNonce = self.msgNonce[:8] + (int.from_bytes(self.msgNonce[8:], 'big') + 1).to_bytes(8, 'big')

    def getPrivateKey(self, path):
        with open(path, 'rb') as f:
            salt, nonce, tag, ciphertext = \
                [f.read(x)
                 for x in (16, 16, 16, -1)]
        fileKey = scrypt(self.password.encode('utf-8'),
                        salt, 16, N=2**20, r=8, p=1)
        cipher_aes = AES.new(fileKey, AES.MODE_GCM, nonce)
        rsaKey = cipher_aes.decrypt_and_verify(ciphertext, tag)
        self.serverRSAprivate = RSA.import_key(rsaKey)
        print("Key Loaded")



class Session:

    def __init__(self, user, key, nonce, workingDir, lastMsg, networkRef, server=os.getcwd(), network=os.getcwd()):
        if 'src' in server:
            server = server.split('src')[0] + 'server'
        self.serverAddress = server
        self.workingDir = workingDir
        self.currentUser = user
        self.lastMsg = lastMsg
        self.msgNonce = nonce
        self.AESKey = key
        # network connection
        if 'src' in network:
            network = network.split('src')[0] + 'network'
        self.networkPath = network
        self.networkRef = networkRef

    def encMsg(self, message, data=b''):
        if isinstance(message, str):
            message = message.encode('utf-8')
        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM, self.msgNonce)
        if(data != b''):
            cipher_text, tag = cipher_aes.encrypt_and_digest(
                message + " ".encode('utf-8') + data)
        else:
            cipher_text, tag = cipher_aes.encrypt_and_digest(message)
        self.incNonce()
        return tag + cipher_text

    def processResp(self, resp):
        tag = resp[:16]
        ciphertext = resp[16:]
        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM, self.msgNonce)
        self.incNonce()
        try:
            plain = cipher_aes.decrypt_and_verify(ciphertext, tag)
            return plain
        except ValueError:
            print('MAC verification failed, ending session...')
            exit(1)

    def writeMsg(self, msg):
        self.networkRef.send_msg(self.currentUser, msg)

    def readMsg(self):
        return self.networkRef.receive_msg()

    def getOsPath(self):
        return self.serverAddress + '/USERS/' + self.currentUser + self.workingDir + "/"

    def incNonce(self):
        self.msgNonce = self.msgNonce[:8] + (int.from_bytes(
            self.msgNonce[8:], 'big') + 1).to_bytes(8, 'big')

    ### COMMANDS ###

    # • MKD – creating a folder on the server
    # • RMD – removing a folder from the server
    # • GWD – asking for the name of the current folder(working directory) on the server
    # • CWD – changing the current folder on the server
    # • LST – listing the content of a folder on the server
    # • UPL – uploading a file to the server
    # • DNL – downloading a file from the server
    # • RMF – removing a file from a folder on the server

    def mkd(self, folderName):
        # makes the directory from the working directory, WARNING accepts paths
        try:
            if self.addressGuard(folderName):
                os.mkdir(self.getOsPath() + '/' + folderName)
                self.writeMsg(self.encMsg("Finished"))
            else:
                self.writeMsg(self.encMsg("Permission Failed"))
        except OSError:
            self.writeMsg(self.encMsg("Mkd Failed"))

    def rmd(self, folderName):
        # removes a directory if it exists, WARNING accepts paths
        try:
            if self.addressGuard(folderName):
                os.rmdir(self.getOsPath() + "/" + folderName)
                self.writeMsg(self.encMsg("Finished"))
            else:
                self.writeMsg(self.encMsg("Permission Failed"))
        except OSError:
            self.writeMsg(self.encMsg("Deletion Failed"))

    def gwd(self):
        # returns the working directory
        self.writeMsg(self.encMsg("Working directory is: " + self.workingDir))

    def cwd(self, newDir):
        # navigates to a new working directory. Checks address for security but also should be secure
        if self.addressGuard(newDir):
            dirs = newDir.split("/")
            for nd in dirs:
                if (nd == ".."):
                    if(self.workingDir == '/root'):
                        break
                    else:
                        self.workingDir = "/".join(self.workingDir.split("/")[:-1])
                else:
                    if(os.path.exists(self.getOsPath() + nd)):
                        self.workingDir = self.workingDir+"/"+nd
        self.writeMsg(self.encMsg(
            "Working directory is now: %s" % self.workingDir))

    def lst(self):
        # lists the contents of the working directory
        dirList = ", ".join(os.listdir(self.serverAddress + '/USERS/' +
                                       self.currentUser + self.workingDir))
        if len(dirList) == 0:
            dirList = '<empty>'
        self.writeMsg(self.encMsg(dirList))

    def upl(self, fileName, data):
        # Uploads a file shouldn't accept paths but check address is run for redundant security
        if self.addressGuard(fileName):
            with open(self.getOsPath()+fileName, 'wb') as f:
                f.write(data)
            self.writeMsg(self.encMsg("%s uploaded" % fileName))
        else:
            self.writeMsg(self.encMsg("Upload Failed"))

    def dnl(self, fileName):
        # Downloads a given filename WARNING: accepts paths
        if self.addressGuard(fileName):
            with open(self.getOsPath()+fileName, "rb") as f:
                data = f.read()
            self.writeMsg(self.encMsg(data))
        else:
            self.writeMsg(self.encMsg("Download Failed"))

    def rmf(self, fileName):
        # Removes a file at the specified filename WARNING: accepts paths which is why the check address is run
        if self.addressGuard(fileName):
            if os.path.exists(self.getOsPath() + fileName):
                os.remove(self.getOsPath() + fileName)
                self.writeMsg(self.encMsg("Removed"))
            else:
                self.writeMsg(self.encMsg("The file does not exist"))
        else:
            self.writeMsg(self.encMsg("Deletion Failed"))

    def addressGuard(self, addr):
        # ensures that whatever address is being passed is within the root directory of the user
        newDir = self.workingDir
        dirs = addr.split("/")
        for nd in dirs:
            if (nd == ".."):
                if(newDir == '/root'):
                    return False
                else:
                    newDir = "/".join(self.workingDir.split("/")[:-1])
            else:
                if(os.path.exists(self.getOsPath() + nd)):
                    newDir = newDir+"/"+nd
        return True


def main(server, network, serverRSA):
    s = Server(server, network, serverRSA)
    # set up session keys and establish secure connection here
    s.initSession()
    while True:
        # wait for message from client
        msg, src = s.readMsg()
        if src in s.sessions:
            msg = s.sessions[src].processResp(msg)
            # parse msg into parts all msgs will be recieved iwht cmd file/foldername payload
            msg = msg.split(' '.encode('utf-8'), 2)
            cmd = msg[0].decode('utf-8').lower()
            if len(msg) > 1:
                args = msg[1:]
                name = args[0].decode('utf-8')
            if cmd == "mkd":
                s.sessions[src].mkd(name)
            elif cmd == "rmd":
                s.sessions[src].rmd(name)
            elif cmd == "gwd":
                s.sessions[src].gwd()
            elif cmd == "cwd":
                s.sessions[src].cwd(name)
            elif cmd == "lst":
                s.sessions[src].lst()
            elif cmd == "upl":
                try:
                    s.sessions[src].upl(name, args[1])
                except:
                    s.sessions[src].writeMsg(s.sessions[src].encMsg("Error"))
            elif cmd == "dnl":
                try:
                    s.sessions[src].dnl(name)
                except:
                    s.sessions[src].writeMsg(s.sessions[src].encMsg("Error"))
            elif cmd == "rmf":
                s.sessions[src].rmf(name)
            elif cmd == "end_session":
                s.sessions[src].writeMsg(s.sessions[src].encMsg("end_session"))
                del s.sessions[src]
            else:
                s.sessions[src].writeMsg(s.sessions[src].encMsg("Invalid command"))
            time.sleep(0.5)
            # print client message
            print(f"Client command: {msg}{' '*20}")
        else:
            s.initSession(msg, src)


try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hs:n:r:', longopts=['help', 'server', 'network', 'serverRSA'])
except getopt.GetoptError:
	print('Usage: python server.py -h)')
	sys.exit(1)

server = None
network = None
serverRSA = None

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python server.py -h <help> -s path_to_server_dir -n path_to_network_dir -r path_to_server_RSA_keys_directory')
        print('All args are optional. Note that if serverRSA is left to default, the server RSA keys must be in the server directory')
        sys.exit(0)
    elif opt == '-s' or opt == '--server':
        server = arg
    elif opt == '-n' or opt == '--network':
        network = arg
    elif opt == '-r' or opt == '--serverRSA':
        serverRSA = arg

main(server, network, serverRSA)
