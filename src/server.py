import os
import sys
import getopt
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


class Server:
    def __init__(self, server=os.getcwd()):
        if 'src' in server:
            server = server.split('src')[0] + 'server'
        self.serverAddress = server
        self.serverRSApublic = self.serverAddress + '/serverRSApublic.pem'
        self.serverRSAprivate = self.serverAddress + '/serverRSAprivate.pem'
        self.workingDir = None
        self.currentUser = None
        self.lastMsg = 0
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
        resp = self.processResp(resp[sizeOfKey:])

        # Authenticate user
        username, password = resp.split(":".encode("utf-8"))
        if (not self.authUser(username.decode('utf-8'), password)):
            print(f'Nice try hacker man, get outta here!')
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

    def encMsg(self, message):
        if(type(message) == type("")):
            message = message.encode('utf-8')

        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM)
        cipher_text, tag = cipher_aes.encrypt_and_digest(message)

        return cipher_aes.nonce + tag + cipher_text

    def processResp(self, resp):
        nonce = resp[:16]
        tag = resp[16:32]
        ciphertext = resp[32:]

        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM, nonce)

        return cipher_aes.decrypt_and_verify(ciphertext, tag)

    def authUser(self, username, passHash):
        if username in os.listdir(self.serverAddress + '/USERS'):
            with open(self.serverAddress + '/USERS/' + username + '/.hash_check.hash', 'rb') as f:
                if passHash == f.read():
                    return True
        return False

    def getResponse(self):
        # add numTries and make it a timeout?
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
            os.mkdir(self.serverAddress + '/USERS/' + self.currentUser + self.workingDir + "/" + folderName)
        except OSError:
            print("Make directory %s failed" % folderName)
        
    def rmd(self, folderName):
        # removes a directory if it exists
        try:
            os.rmdir(self.serverAddress + '/USERS/' +
                    self.currentUser + self.workingDir + "/" + folderName)
        except OSError:
            print("Deletion of the directory %s failed" % folderName)
    
    def gwd(self):
        self.writeMsg(self.encMsg(self.workingDir))
    
    def cwd(self, newDir):
        if (newDir == ".." and self.workingDir != '/root'):
            "".join(self.workingDir.split("/")[-1])
            pass
        elif (newDir != ".."):
            if(self.workingDir + "/" + newDir in os.listdir(self.workingDir)):
                self.workingDir = self.workingDir+"/"+newDir
    
    def lst(self):
        dirList = ", ".join(os.listdir(self.serverAddress + '/USERS/' +
                                     self.currentUser + self.workingDir))
        self.writeMsg(self.encMsg(dirList))


def main():
    s = Server()
    # set up session keys and establish secure connection here
    s.initSession()
    s.gwd()
    s.mkd("test2")
    s.mkd("test3")
    s.mkd("test4")
    s.lst()
    s.rmd("test2")
    s.lst()
    # while True:
    #     # wait for message from client, eventually going to need command parsing (yuck!)
    #     response = False
    #     cycles = 0
    #     while (not response):
    #         print('Waiting' + '.'*(cycles%4) + ' '*4, end='\r')
    #         msg = s.readMsg()
    #         if msg != '':
    #             response = True
    #         time.sleep(0.5)
    #         cycles += 1
    #     # print client message (for debugging)
    #     print(f"Client command: {msg}{' '*20}")
    #     # send response to client (this will be other stuff eventually)
    #     msg = 'Message received.'
    #     s.writeMsg(msg)
    #     time.sleep(0.5)

main()
