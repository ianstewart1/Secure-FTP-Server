
import os
import sys
import getopt
import time
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt


class Client:
    def __init__(self, client=os.getcwd()):
        # TODO: Fix so that user input for client is supported
        self.clientAddress = client.split('src')[0] + 'client'
        self.clientRSAprivate = self.clientAddress + '/clientRSAprivate.pem'
        self.clientRSApublic = self.clientAddress + '/clientRSApublic.pem'
        self.serverRSApublic = self.clientAddress + '/serverRSApublic.pem'
        # used for keeping track of new messages
        self.lastMsg = 0
        # set after initSession - current session keys
        self.MACKey = None
        self.AESKey = None
        self.iv = None

    def initSession(self):
        print('Establishing session...')
        with open(self.clientRSAprivate, 'rb') as f:
            self.clientRSAprivate = RSA.import_key(f.read())
        with open(self.clientRSApublic, 'rb') as f:
            self.clientRSApublic = RSA.import_key(f.read())
        with open(self.serverRSApublic, 'rb') as f:
            self.serverRSApublic = RSA.import_key(f.read())
        # client generate a key (master key)
        masterKey = get_random_bytes(32)
        encryptRSAcipher = PKCS1_OAEP.new(self.serverRSApublic)
        # send master key, nonce and client public key to server encrypted with server public key
        msg = encryptRSAcipher.encrypt(masterKey + self.clientRSApublic) # MAC????
        self.writeMsg(msg)
        # wait for server response
        resp = self.getResponse()
        # decrypt response from server
        decryptRSAcipher = PKCS1_OAEP.new(self.clientRSAprivate)
        resp = decryptRSAcipher.decrypt(resp)
        if (resp != masterKey):
            print('Response master key does not match. Ending session setup...')
            exit(1)
        # use key derivation protocol scrypt to get unique MAC (HMAC/SHA256) and ENC keys for an AES cipher(CBC)
        salt = get_random_bytes(32)
        keys = scrypt(masterKey, salt, 32, 2**20, 8, 1, 2)
        # set client variables
        self.MACKey = keys[0]
        self.AESKey = keys[1]
        msg = encryptRSAcipher.encrypt(keys[0] + keys[1])
        self.writeMsg(msg)
        # wait for server response
        resp = self.getResponse()
        # decrypt
        resp = decryptRSAcipher.decrypt(resp)
        if (resp[:32] != self.MACKey or resp[32:] != self.AESKey):
            print('Response MAC or AES key does not match. Ending session setup...')
            exit(1)
        print('Session established')

    def getResponse(self):
        response = False
        while (not response):
            resp = self.readMsg()
            if resp != '':
                response = True
        return resp

    def login(self):
        # called at the start of the session
        pass

    def encryptFile(self, file):
        # because server should not have plaintext
        pass

    def writeMsg(self, msg):
        msgs = sorted(os.listdir(self.clientAddress + '/OUT/'))
        if len(msgs) > 0:
            nextMsg = (int.from_bytes(bytes.fromhex(msgs[-1]), 'big') + 1).to_bytes(2, 'big').hex()
        else:
            nextMsg = '0000'
        with open(self.clientAddress + '/OUT/' + nextMsg, 'w') as m:
            m.write(msg)

    def readMsg(self):
        msgs = sorted(os.listdir(self.clientAddress + '/IN'))
        if len(msgs) > self.lastMsg:
            self.lastMsg += 1
            with open(self.clientAddress + '/IN/' + msgs[-1], 'r') as m:
                return m.read()
        return ''


def main():
    c = Client()
    # set up session keys and establish secure connection here
    c.initSession()
    while True:
        # send message to server
        msg = ''
        while msg == '':
            # here is where user will send commands to server in the future
            msg = input('Msg: ')
        c.writeMsg(msg)
        # wait for response from server
        response = False
        while (not response):
            msg = c.readMsg()
            if msg != '':
                response = True
        # print server response
        print(f'Server: {msg}')
        time.sleep(0.5)

main()