import os
import getopt, getpass
import time
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256


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
        # set after initSession - session keys
        self.AESKey = None
        # user params
        self.username = None
        self.password = None

    def initializeSession(self):
        print('Establishing session...')
        self.login()

        self.AESkey = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.serverRSApublic)
        enc_session_key = cipher_rsa.encrypt(self.AESkey)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(self.AESkey, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest((self.username + ":" + str(self.password)).encode('utf-8'))

        # Send first message
        self.writeMsg(enc_session_key + cipher_aes.nonce + tag + ciphertext)

        resp = self.getResponse()

        # Process Server Response
        nonce, tag, ciphertext = self.processResp(resp)

        cipher_aes = AES.new(self.AESkey, AES.MODE_GCM, nonce)


        resp = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Check if the server is logging in the right person
        if(resp.decode('utf-8') != self.username):
            print("fuck me")
            print(resp)
            exit(1)
        print('Session established')

    def processResp(self, resp):
        nonce = resp[:16]
        tag = resp[16:32]
        ciphertext = resp[32:]

        return nonce, tag, ciphertext

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
        # called at the start of the 
        userN = ''
        passwrd = ''
        while userN == '' or passwrd == '':
            userN = input("Enter your username: ")
            passwrd = getpass.getpass("Enter your password: ")
        self.username = userN
        h = SHA256.new(data=passwrd.encode('utf-8'))
        self.password = h.digest()

    def encryptFile(self, file_in, file_out=''):
        if file_out == '':
            file_out = file_in
        # because server should not have plaintext
        with open(file_in, 'rb') as f:
            data = f.read()

        session_key = get_random_bytes(16)
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.clientRSApublic)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        with open(file_out, "wb") as f:
            [f.write(x)
             for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

    def decryptFile(self, file):
        file_in = open(file, "rb")

        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x)
             for x in (self.clientRSAprivate.size_in_bytes(), 16, 16, -1)]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(self.clientRSAprivate)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
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
    c.initializeSession()
    # set up session keys and establish secure connection here
    print(c.AESKey)
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








# def initSession(self):
    #     print('Establishing session...')
    #     self.loadRSAKeys()
    #     # client generate master key
    #     self.initialCheck()
    #     # use key derivation protocol scrypt to get unique MAC (HMAC/SHA256) and ENC keys for an AES cipher(CBC)
    #     self.createKeys(self.AESKey)
    #     self.login()
    #     print('Session established')

    # def createKeys(self, masterKey, iv):
    #     # set client variables
    #     AEScipher = AES.new(masterKey, AES.MODE_GCM)
        
        
    #     msg = AEScipher.encrypt(pad(keys[0] + keys[1], AES.block_size))
    #     self.writeMsg(msg)
    #     # wait for server response
    #     resp = self.getResponse()
    #     # decrypt server response and check MAC/AES key values
    #     AEScipher = AES.new(masterKey, AES.MODE_CBC, iv)
    #     resp = unpad(AEScipher.decrypt(resp), AES.block_size)
    #     if (resp[:32] != self.MACKey or resp[32:] != self.AESKey):
    #         print('Response MAC or AES key does not match. Ending session setup...')
    #         exit(1)

    # def initialCheck(self):
    #     masterKey = get_random_bytes(32)
    #     encryptRSAcipher = PKCS1_OAEP.new(self.serverRSApublic)
    #     # send master key to server encrypted with server public key
    #     msg = encryptRSAcipher.encrypt(masterKey) 
    #     self.writeMsg(msg)
    #     # wait for server response
    #     resp = self.getResponse()
    #     # decrypt response from server
    #     AEScipher = AES.new(masterKey, AES.MODE_GCM)
    #     resp = AEScipher.decrypt(resp), AES.block_size
    #     if (resp != masterKey):
    #         print('Response master key does not match. Ending session setup...')
    #         exit(1)
    #     return masterKey, iv
