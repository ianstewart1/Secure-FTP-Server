import os
import getopt
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256


class Server:

    ## INITIALIZATION
    
    def __init__(self, server=os.getcwd()):
        if 'src' in server:
            server = server.split('src')[0] + 'server'
        self.serverAddress = server
        self.serverRSApublic = self.serverAddress + '/serverRSApublic.pem'
        self.serverRSAprivate = self.serverAddress + '/serverRSAprivate.pem'
        self.workingDir = None
        self.currentUser = None
        self.lastMsg = 0
        self.msgNonce = None
        self.AESKey = None

    def initSession(self):
        self.loadRSAKeys()
        # wait for client message
        resp = self.getResponse()

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
        username, password = resp.split(":".encode("utf-8"))
        h = SHA256.new(data=password)
        password = h.digest()
        if (not self.authUser(username.decode('utf-8'), password)):
            print('Nice try hacker man, get outta here!')
            exit(1)

        self.currentUser = username.decode('utf-8')
        self.workingDir = '/root'

        # Create response if login was successful
        serverResponse = self.encMsg(self.currentUser)
        self.writeMsg(serverResponse)

    def loadRSAKeys(self):
        with open(self.serverRSApublic, 'rb') as f:
            self.serverRSApublic = RSA.import_key(f.read())
        with open(self.serverRSAprivate, 'rb') as f:
            self.serverRSAprivate = RSA.import_key(f.read())

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

    def getResponse(self):
        response = False
        while (not response):
            resp = self.readMsg()
            if resp != '':
                response = True
        return resp

    def writeMsg(self, msg):
        msgs = sorted(os.listdir(self.serverAddress + '/OUT/'))
        if len(msgs) > 0:
            nextMsg = (int.from_bytes(bytes.fromhex(msgs[-1]), 'big') + 1).to_bytes(2, 'big').hex()
        else:
            nextMsg = '0000'
        with open(self.serverAddress + '/OUT/' + nextMsg, 'wb') as m:
            m.write(msg)

    def readMsg(self):
        msgs = sorted(os.listdir(self.serverAddress + '/IN'))
        if len(msgs) > self.lastMsg:
            self.lastMsg += 1
            with open(self.serverAddress + '/IN/' + msgs[-1], 'rb') as m:
                return m.read()
        return ''

    def getOsPath(self):
        return self.serverAddress + '/USERS/' + self.currentUser + self.workingDir + "/"

    def clearMsgs(self):
        for msg in os.listdir(self.serverAddress + '/IN'): os.remove(self.serverAddress + '/IN/' + msg)
        for msg in os.listdir(self.serverAddress + '/OUT'): os.remove(self.serverAddress + '/OUT/' + msg)

    def incNonce(self):
        self.msgNonce = self.msgNonce[:8] + (int.from_bytes(self.msgNonce[8:], 'big') + 1).to_bytes(8, 'big')

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
            os.mkdir(self.getOsPath() + folderName)
            self.writeMsg(self.encMsg("Finished"))
        except OSError:
            self.writeMsg(self.encMsg("Mkd Failed"))
        
    def rmd(self, folderName):
        # removes a directory if it exists
        try:
            os.rmdir(self.getOsPath() + folderName)
            self.writeMsg(self.encMsg("Finished"))
        except OSError:
            self.writeMsg(self.encMsg("Deletion Failed"))
    
    def gwd(self):
        self.writeMsg(self.encMsg("Working directory is: " + self.workingDir))
    
    def cwd(self, newDir):
        dirs = newDir.split("/")
        for nd in dirs:
            print(nd)
            if (nd == ".."):
                if(self.workingDir == '/root'):
                    self.writeMsg(self.encMsg(
                        "Working directory is now: %s" % self.workingDir))
                    return
                else:
                    self.workingDir = "/".join(self.workingDir.split("/")[:-1])
            elif (nd != ".."):
                if(os.path.exists( self.getOsPath() + newDir)):
                    self.workingDir = self.workingDir+"/"+newDir
        self.writeMsg(self.encMsg("Working directory is now: %s" %self.workingDir))
    
    def lst(self):
        dirList = ", ".join(os.listdir(self.serverAddress + '/USERS/' +
                                     self.currentUser + self.workingDir))
        if len(dirList) == 0:
            dirList = '<empty>'
        self.writeMsg(self.encMsg(dirList))

    def upl(self, fileName, data):
        with open(self.getOsPath()+fileName, 'wb') as f:
            f.write(data)
        self.writeMsg(self.encMsg("%s uploaded" %fileName))

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


def main():
    s = Server()
    s.clearMsgs()
    # set up session keys and establish secure connection here
    s.initSession()
    while True:
        # wait for message from client, eventually going to need command parsing (yuck!)
        response = False
        cycles = 0
        while (not response):
            print('Waiting' + '.'*(cycles%4) + ' '*4, end='\r')
            msg = s.readMsg()
            if msg != '':
                response = True
                msg = s.processResp(msg)
                # parse msg into parts all msgs will be recieved iwht cmd file/foldername payload
                msg = msg.split(' '.encode('utf-8'), 2)
                cmd = msg[0].decode('utf-8').lower()
                if len(msg) > 1:
                    args = msg[1:]
                    name = args[0].decode('utf-8')
                # print("msg: %s" % msg)
                if cmd == "mkd":
                    s.mkd(name)
                elif cmd == "rmd":
                    s.rmd(name)
                elif cmd == "gwd":
                    s.gwd()
                elif cmd == "cwd":
                    s.cwd(name)
                elif cmd == "lst":
                    s.lst()
                elif cmd == "upl":
                    try:
                        # print(name)
                        # print(b''.join(args[1:]))
                        s.upl(name, args[1])
                    except:
                        s.writeMsg(s.encMsg("Error"))
                elif cmd == "dnl":
                    try:
                        s.dnl(name)
                    except:
                        s.writeMsg(s.encMsg("Error"))
                elif cmd == "rmf":
                    s.rmf(name)
                else:
                    s.writeMsg(s.encMsg("Invalid command"))
            time.sleep(0.5)
            cycles += 1
        # print client message (for debugging)
        print(f"Client command: {msg}{' '*20}")
        # send response to client (this will be other stuff eventually)
        # msg = 'Message received.'
        # s.writeMsg(msg)
        time.sleep(0.5)


main()
