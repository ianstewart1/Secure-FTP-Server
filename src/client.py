import os
import getopt
import getpass
import time
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
        self.serverRSApublic = self.clientAddress + '/serverRSApublic.pem'
        # used for keeping track of new messages
        self.lastMsg = 0
        self.msgNonce = None
        # set after initSession - session key
        self.AESKey = None
        # user params
        self.username = None
        self.password = None

    def initializeSession(self):
        print('Establishing session...')
        self.login()

        self.AESKey = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.serverRSApublic)
        enc_session_key = cipher_rsa.encrypt(self.AESKey)

        # Encrypt the data with the AES session key
        cipherContent = self.username.encode(
            'utf-8') + ':'.encode('utf-8') + self.password.encode('utf-8')
        # Initilize AES nonce (replay protection)
        zero = 0
        randomBytes = get_random_bytes(8)
        self.msgNonce = randomBytes + zero.to_bytes(8, 'big')
        
        messageContent = self.encMsg(cipherContent)

        # Send first message
        self.writeMsg(enc_session_key + randomBytes + messageContent)

        # Receive and Process Server Response
        resp = self.processResp(self.getResponse())

        # Check if the server is logging in the right person
        if resp.decode('utf-8') != self.username:
            print('Username from server did not match, quitting')
            exit(1)
        print('Session established')

    def encMsg(self, message, data=b''):
        if isinstance(message, str):
            message = message.encode('utf-8')
        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM, self.msgNonce)
        if data!=b'':
            cipher_text, tag = cipher_aes.encrypt_and_digest(message + " ".encode('utf-8') + data)
        else:
            cipher_text, tag = cipher_aes.encrypt_and_digest(message)
        self.incNonce()
        return tag + cipher_text

    def processResp(self, resp):
        """
        Takes in a message and returns the plaintext using the AESKey
        """
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

    def loadRSAKeys(self):
        with open(self.serverRSApublic, 'rb') as f:
            self.serverRSApublic = RSA.import_key(f.read())

    def getResponse(self):
        """Awaits a response from the server. Returns content when one is detected"""
        response = False
        while (not response):
            resp = self.readMsg()
            if resp != '':
                response = True
        return resp

    def login(self):
        # called at the start of a session
        userN = ''
        passwrd = ''
        while userN == '' or passwrd == '':
            userN = input("Enter your username: ")
            passwrd = getpass.getpass("Enter your password: ")
        self.username = userN
        self.password = passwrd

    def encryptFile(self, file_in, file_out=''):
        # because server should not have plaintext
        with open(self.clientAddress + '/' + file_in, 'rb') as f:
            data = f.read()
        
        salt = get_random_bytes(16)
        keyKey = scrypt(self.password.encode('utf-8'), salt, 16, N=2**14, r=8, p=1)
        print(keyKey)
        session_key = get_random_bytes(16)
        # Encrypt the file key
        cipher_aes = AES.new(keyKey, AES.MODE_GCM)
        enc_session_key, keyTag = cipher_aes.encrypt_and_digest(session_key)
        keyNonce = cipher_aes.nonce
        print(enc_session_key)

        # Encrypt the data with the AES file key
        cipher_aes = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        # If we want to write to another file
        if file_out != '':
            with open(self.clientAddress + '/' + file_out, 'wb') as f:
                [f.write(x)
                 for x in (salt, keyTag, keyNonce, enc_session_key, cipher_aes.nonce, tag, ciphertext)]
        return salt + keyTag + keyNonce + enc_session_key + cipher_aes.nonce + tag + ciphertext

    def decryptFile(self, path):
        # TODO: Re-write to take in byte string rather than opening a file that has just been written
        path = self.clientAddress + '/' + path
        file_in = open(path, 'rb')
        salt, keyTag, keyNonce, enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x)
             for x in (16, 16, 16, 16, 16, 16, -1)]  # (keyTag, keyNonce, key, nonce, tag, ciphertext)
        file_in.close()

        keyKey = scrypt(self.password.encode('utf-8'),
                        salt, 16, N=2**14, r=8, p=1)
        print(keyKey)
        # Decrypt the session key with the public RSA key
        cipher_aes = AES.new(keyKey, AES.MODE_GCM, keyNonce)
        session_key = cipher_aes.decrypt_and_verify(enc_session_key, keyTag)

        # # Decrypt the session key with the private RSA key
        # cipher_rsa = PKCS1_OAEP.new(self.clientRSAprivate)
        # session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        with open(path, 'wb') as f:
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
        
    def clearMsgs(self):
        for msg in os.listdir(self.clientAddress + '/IN'): os.remove(self.clientAddress + '/IN/' + msg)
        for msg in os.listdir(self.clientAddress + '/OUT'): os.remove(self.clientAddress + '/OUT/' + msg)

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


def main():
    # TODO: add getopt to specify client folder destination
    c = Client()
    c.clearMsgs()
    c.loadRSAKeys()
    c.initializeSession()
    # set up session keys and establish secure connection here
    while True:
        # send message to server
        msg = ''
        while msg == '':
            msg = input('Command: ')
            if msg[:3] == 'upl':
                data = c.encryptFile(msg[4:])
                c.writeMsg(c.encMsg(msg, data))
            elif msg[:3] == 'dnl':
                c.writeMsg(c.encMsg(msg))
                data = c.processResp(c.getResponse())
                with open(c.clientAddress + '/' + msg[4:], 'wb') as f:
                    f.write(data)
                c.decryptFile(msg[4:])
            else:
                c.writeMsg(c.encMsg(msg))
        # wait for response from server
        if msg[:3] == 'dnl':
            msg = msg[4:] + ' downloaded'
        else:
            msg = c.processResp(c.getResponse()).decode('utf-8')
        # print server response
        print(msg)
        time.sleep(0.5)


main()
