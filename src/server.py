import os
import getopt
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from netinterface import network_interface


class Server:

    ## INITIALIZATION
    
    def __init__(self, server=os.getcwd(), network=os.getcwd()):
        if 'src' in server:
            server = server.split('src')[0] + 'server'
        self.serverAddress = server
        self.serverRSApublic = self.serverAddress + '/serverRSApublic.pem'
        self.serverRSAprivate = self.serverAddress + '/serverRSAprivate.pem'
        with open(self.serverRSApublic, 'rb') as f:
            self.serverRSApublic = RSA.import_key(f.read())
        with open(self.serverRSAprivate, 'rb') as f:
            self.serverRSAprivate = RSA.import_key(f.read())
        self.workingDir = None
        self.currentUser = None
        self.lastMsg = 0
        self.msgNonce = None
        self.AESKey = None
        # network connection
        if 'src' in network:
            network = network.split('src')[0] + 'network'
        self.networkPath = network
        self.networkRef = None
        self.sessions = {}

    def initSession(self, resp = '', src = ''):
        self.networkRef = network_interface(self.networkPath, 'server')
        # wait for client message
        if resp == '' and src == '':
            resp, src = self.readMsg()

        decryptRSAcipher = PKCS1_OAEP.new(self.serverRSAprivate)
        sizeOfKey = self.serverRSApublic.size_in_bytes()

        # Parse out and decrypt session key
        enc_session_key = resp[:sizeOfKey] 
        self.AESKey = decryptRSAcipher.decrypt(enc_session_key)

        # Get message content
        zero = 0
        self.msgNonce = resp[sizeOfKey:sizeOfKey+8] + zero.to_bytes(8, 'big')
        resp = self.processResp(resp[sizeOfKey+8:])

        # Authenticate user
        auth_type, username, password = resp.split(":".encode("utf-8"), 3)
        h = SHA256.new(data=password)
        password = h.digest()
        if auth_type.decode('utf-8') == "newusr":
            self.createNewUser(username.decode('utf-8'), password)
        if (not self.authUser(username.decode('utf-8'), password)):
            print('Nice try hacker man, get outta here!')
            exit(1)

        self.currentUser = username.decode('utf-8')
        self.workingDir = '/root'

        # Create response if login was successful
        serverResponse = self.encMsg(self.currentUser)
        self.writeMsg(serverResponse)

        self.sessions[self.currentUser] = Session(self.currentUser, self.AESKey, self.msgNonce, self.workingDir, self.lastMsg, self.networkRef)
        

    def createNewUser(self, username, passHash):
        userfolder = self.serverAddress + "/USERS/" + username
        if os.path.exists(userfolder):
            self.writeMsg(self.encMsg("Invalid Username"))
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

    def writeMsg(self, msg):
        self.networkRef.send_msg(self.currentUser, msg)

    def readMsg(self):
        return self.networkRef.receive_msg()

    def getOsPath(self):
        return self.serverAddress + '/USERS/' + self.currentUser + self.workingDir + "/"

    def incNonce(self):
        self.msgNonce = self.msgNonce[:8] + (int.from_bytes(self.msgNonce[8:], 'big') + 1).to_bytes(8, 'big')


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
        # makes the directory from the working directory
        try:
            if self.checkAddress(folderName):
                os.mkdir(self.getOsPath() + '/' + folderName)
                self.writeMsg(self.encMsg("Finished"))
            else:
                self.writeMsg(self.encMsg("Permition Failed"))
        except OSError:
            self.writeMsg(self.encMsg("Mkd Failed"))

    def rmd(self, folderName):
        # removes a directory if it exists
        try:
            if self.checkAddress(folderName):
                os.rmdir(self.getOsPath() + "/" + folderName)
                self.writeMsg(self.encMsg("Finished"))
            else:
                self.writeMsg(self.encMsg("Permition Failed"))
        except OSError:
            self.writeMsg(self.encMsg("Deletion Failed"))

    def gwd(self):
        self.writeMsg(self.encMsg("Working directory is: " + self.workingDir))

    def cwd(self, newDir):
        if self.checkAddress(newDir):
            dirs = newDir.split("/")
            for nd in dirs:
                if (nd == ".."):
                    if(self.workingDir == '/root'):
                        return False
                    else:
                        self.workingDir = "/".join(self.workingDir.split("/")[:-1])
                else:
                    if(os.path.exists(self.getOsPath() + nd)):
                        self.workingDir = self.workingDir+"/"+nd
        else:
            self.writeMsg(self.encMsg("Permission Failed"))
        self.writeMsg(self.encMsg(
            "Working directory is now: %s" % self.workingDir))

    def lst(self):
        dirList = ", ".join(os.listdir(self.serverAddress + '/USERS/' +
                                       self.currentUser + self.workingDir))
        if len(dirList) == 0:
            dirList = '<empty>'
        self.writeMsg(self.encMsg(dirList))

    def upl(self, fileName, data):
        with open(self.getOsPath()+fileName, 'wb') as f:
            f.write(data)
        self.writeMsg(self.encMsg("%s uploaded" % fileName))

    def dnl(self, fileName):
        with open(self.getOsPath()+fileName, "rb") as f:
            data = f.read()
        self.writeMsg(self.encMsg(data))

    def rmf(self, fileName):
        if os.path.exists(self.getOsPath() + fileName):
            os.remove(self.getOsPath() + fileName)
            self.writeMsg(self.encMsg("Removed"))
        else:
            self.writeMsg(self.encMsg("The file does not exist"))

    def checkAddress(self, addr):
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
        print(newDir)
        return True


def main():
    s = Server()
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
                print("bye")
                del s.sessions[src]
            else:
                print(cmd)
                s.sessions[src].writeMsg(s.sessions[src].encMsg("Invalid command"))
            time.sleep(0.5)
            # print client message
            print(f"Client command: {msg}{' '*20}")
            # time.sleep(0.5)
        else:
            print(src)
            s.initSession(msg, src)


main()
