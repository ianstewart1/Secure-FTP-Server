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
        self.lastMsg = 0
        self.AESKey = None

    def initSession(self):
        self.loadRSAKeys()
        # wait for client message
        resp = self.getResponse()
        # decrypt message from client
        decryptRSAcipher = PKCS1_OAEP.new(self.serverRSAprivate)
        sizeOfKey = self.serverRSApublic.size_in_bytes()
        # Parse response into relevant parts
        enc_session_key = resp[:sizeOfKey] 
        nonce, tag, ciphertext = self.processResp(resp[sizeOfKey:])
        
        self.AESKey = decryptRSAcipher.decrypt(enc_session_key)

        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM, nonce)

        resp = cipher_aes.decrypt_and_verify(ciphertext, tag)
        username, password = resp.split(":".encode('utf-8'))
        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM)
        serverResponse, tag = cipher_aes.encrypt_and_digest(username)
        
        self.writeMsg(cipher_aes.nonce + tag + serverResponse)

    def loadRSAKeys(self):
        with open(self.serverRSApublic, 'rb') as f:
            self.serverRSApublic = RSA.import_key(f.read())
        with open(self.serverRSAprivate, 'rb') as f:
            self.serverRSAprivate = RSA.import_key(f.read())

    def processResp(self, resp):
        nonce = resp[:16]
        tag = resp[16:32]
        ciphertext = resp[32:]

        return nonce, tag, ciphertext

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


def main():
    s = Server()
    # set up session keys and establish secure connection here
    s.initSession()
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
