
import os
import sys
import getopt
import time
import json
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad


class Client:
    def __init__(self, client=os.getcwd()):
        if 'src' in client:
            client = client.split('src')[0] + 'client'
        self.clientAddress = client
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
        self.loadRSAKeys()
        # client generate master key
        masterKey, iv = self.initialCheck()
        # use key derivation protocol scrypt to get unique MAC (HMAC/SHA256) and ENC keys for an AES cipher(CBC)
        self.createKeys(masterKey, iv)
        print('Session established')

    def createKeys(self, masterKey, iv):
        # use key derivation protocol scrypt to get unique MAC (HMAC/SHA256) and ENC keys for an AES cipher(CBC)
        salt = get_random_bytes(32)
        keys = scrypt(masterKey, salt, 32, 2**20, 8, 1, 2)
        # set client variables
        self.MACKey = keys[0]
        self.AESKey = keys[1]
        AEScipher = AES.new(masterKey, AES.MODE_CBC, iv)
        msg = AEScipher.encrypt(pad(keys[0] + keys[1], AES.block_size))
        self.writeMsg(msg)
        # wait for server response
        resp = self.getResponse()
        # decrypt server response and check MAC/AES key values
        AEScipher = AES.new(masterKey, AES.MODE_CBC, iv)
        resp = unpad(AEScipher.decrypt(resp), AES.block_size)
        if (resp[:32] != self.MACKey or resp[32:] != self.AESKey):
            print('Response MAC or AES key does not match. Ending session setup...')
            exit(1)

    def initialCheck(self):
        masterKey = get_random_bytes(32)
        iv = get_random_bytes(AES.block_size)
        encryptRSAcipher = PKCS1_OAEP.new(self.serverRSApublic)
        # send master key to server encrypted with server public key
        msg = encryptRSAcipher.encrypt(masterKey + iv) 
        self.writeMsg(msg)
        # wait for server response
        resp = self.getResponse()
        # decrypt response from server
        AEScipher = AES.new(masterKey, AES.MODE_CBC, iv)
        resp = unpad(AEScipher.decrypt(resp), AES.block_size)
        if (resp != masterKey):
            print('Response master key does not match. Ending session setup...')
            exit(1)
        return masterKey, iv

    def loadRSAKeys(self):
        with open(self.clientRSAprivate, 'rb') as f:
            self.clientRSAprivate = RSA.import_key(f.read())
        with open(self.clientRSApublic, 'rb') as f:
            self.clientRSApublic = RSA.import_key(f.read())
        with open(self.serverRSApublic, 'rb') as f:
            self.serverRSApublic = RSA.import_key(f.read())

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

    def encryptFile(self, file_in, file_out = ""):
        if(file_out == ""):
            file_out = file_in
        # because server should not have plaintext
        with open(file_in, 'rb') as f:
            data = f.read()
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.clientRSApublic)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        with open(file_out, "wb") as f:
            [f.write(x)
             for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

    def decryptFile(self, file):
        file_in = open(file, "rb")

        private_key = self.clientRSAprivate

        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x)
             for x in (private_key.size_in_bytes(), 16, 16, -1)]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        with open(file, "wb") as f:
            f.write(data)

    def writeMsg(self, msg):
        msgs = sorted(os.listdir(self.clientAddress + '/OUT/'))
        if len(msgs) > 0:
            nextMsg = (int.from_bytes(bytes.fromhex(
                msgs[-1]), 'big') + 1).to_bytes(2, 'big').hex()
        else:
            nextMsg = '0000'
        with open(self.clientAddress + '/OUT/' + nextMsg, 'wb') as m:
            m.write(msg)

    def readMsg(self):
        msgs = sorted(os.listdir(self.clientAddress + '/IN'))
        if len(msgs) > self.lastMsg:
            self.lastMsg += 1
            with open(self.clientAddress + '/IN/' + msgs[-1], 'rb') as m:
                return m.read()
        return ''


def main():
    c = Client()
    c.loadRSAKeys()
    f = open("test.txt", "w+")
    data = "let's encrypt!"
    f.write(data)
    f.close()
    c.encryptFile("test.txt", "test1.txt")
    c.decryptFile("test1.txt")
    # set up session keys and establish secure connection here
    # c.initSession()
    # print(c.MACKey)
    # print(c.AESKey)
    # while True:
    #     # send message to server
    #     msg = ''
    #     while msg == '':
    #         # here is where user will send commands to server in the future
    #         msg = input('Msg: ')
    #     c.writeMsg(msg)
    #     # wait for response from server
    #     response = False
    #     while (not response):
    #         msg = c.readMsg()
    #         if msg != '':
    #             response = True
    #     # print server response
    #     print(f'Server: {msg}')
    #     time.sleep(0.5)


main()
