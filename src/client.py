
import os
import sys
import getopt
import time

class Client:
    def __init__(self, client=os.getcwd()):
        self.clientAddress = client.split('src')[0] + 'client'
        self.lastMsg = 0
        # set after initSession - current session keys
        self.MACKey = None
        self.AESKey = None

    def initSession(self):
        # generate an 'x' value for DH (store gx)                                *Use this? https://github.com/deadPix3l/pyDHE/blob/master/lib/pyDHE/
        # client sends username and (g**x)%p to server (encrypted/signed???)
        # server should respond with (username, gx, gy) signed with server private key, and (g**y)%p
        #   - client checks validity of signature and then checks if gx correct (ie. 'server' was able to read last message)
        # client then sends back (username, gx, gy) signed with private signature key
        #   - server checks validity of signature and checks if gy is correct (ie. 'client' is same client as in first message)
        # from here, the master key is computed by both parties and key derivation ensues...

        # use key derivation protocol from pycrypto (scrypt or bcrypt) to get unique MAC (HMAC/SHA256) and ENC keys for an AES cipher(CBC)
        #   - client should compute and send over?

        # when does the user send over their public key so that the server can verify signatures?
        pass

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