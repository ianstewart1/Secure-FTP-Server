import os
import getopt
import getpass
import time
import sys
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from netinterface import network_interface


class Client:

    def __init__(self, client, network, serverRSA):
        if client == None:
            client = os.getcwd().split('src')[0] + 'client'
            if not os.path.exists(client):
                os.mkdir(client)
        self.clientAddress = client
        if serverRSA == None:
            self.serverRSApublic = self.clientAddress + '/serverRSApublic.pem'
        # used for keeping track of new messages
        self.lastMsg = 0
        self.msgNonce = None
        # set after initSession - session key
        self.AESKey = None
        # user params
        self.username = None
        self.password = None
        # network connection
        if network == None:
            network = os.getcwd().split('src')[0] + 'network'
            if not os.path.exists(network):
                os.mkdir(network)
        self.networkPath = network
        self.networkRef = None

    def initializeSession(self, newUser):
        print('Establishing session...')
        self.login()
        # initialize network connection
        self.networkRef = network_interface(self.networkPath, self.username)
        # get a random bytestring to use as key
        self.AESKey = get_random_bytes(16)

        # Encrypt the session key with the server's public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.serverRSApublic)
        enc_session_key = cipher_rsa.encrypt(self.AESKey)

        # encrypt the data with the AES session key
        if not newUser:
            plaintext = "login:".encode('utf-8') + self.username.encode(
                'utf-8') + ':'.encode('utf-8') + self.password.encode('utf-8')
        else:
            plaintext = "newusr:".encode('utf-8') + self.username.encode(
                'utf-8') + ':'.encode('utf-8') + self.password.encode('utf-8')

        # initilize AES nonce (replay protection)
        #   first 8 bytes are randomly generated for each session, last 8 bytes are a counter
        zero = 0
        randomBytes = get_random_bytes(8)
        self.msgNonce = randomBytes + zero.to_bytes(8, 'big')
        # encrypt plaintext message and prepend with cipher tag
        messageContent = self.encMsg(plaintext)

        # send first message
        self.writeMsg(enc_session_key + randomBytes + messageContent)

        # receive and Process Server Response
        resp = self.processResp(self.readMsg())

        # check if the server received and properly decoded the message
        if resp.decode('utf-8') != self.username:
            print('Communication error, quitting')
            exit(1)

        print('Session established')

    def encMsg(self, message, data=b''):
        if isinstance(message, str):
            message = message.encode('utf-8')
        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM, self.msgNonce)
        if data != b'':
            cipher_text, tag = cipher_aes.encrypt_and_digest(message + " ".encode('utf-8') + data)
        else:
            cipher_text, tag = cipher_aes.encrypt_and_digest(message)
        # increment local instance of message nonce used to set up AES GCM cipher
        self.incNonce()
        return tag + cipher_text

    def processResp(self, resp):
        # takes in a message and returns the plaintext using the AESKey
        tag = resp[:16]
        ciphertext = resp[16:]
        cipher_aes = AES.new(self.AESKey, AES.MODE_GCM, self.msgNonce)
        # we must increment when we receive a message too, as we only have one counter
        self.incNonce()
        try:
            plain = cipher_aes.decrypt_and_verify(ciphertext, tag)
            if(plain=="end_session"):
                sys.exit(1)
            return plain
        except ValueError:
            print('MAC verification failed, ending session...')
            exit(1)

    def loadRSAKeys(self):
        # called during session intialization to load the server's public RSA key for use in the first message to server
        with open(self.serverRSApublic, 'rb') as f:
            self.serverRSApublic = RSA.import_key(f.read())

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
        # because server should never have access to plaintext file data
        with open(self.clientAddress + '/' + file_in, 'rb') as f:
            data = f.read()
        
        # derive file key from user password
        salt = get_random_bytes(16)
        masterFile = scrypt(self.password.encode('utf-8'), salt, 16, N=2**20, r=8, p=1)
        fileKey = get_random_bytes(16)

        # encrypt the file key
        cipher_aes = AES.new(masterFile, AES.MODE_GCM)
        enc_file_key, keyTag = cipher_aes.encrypt_and_digest(fileKey)
        keyNonce = cipher_aes.nonce

        # encrypt the data with the AES file key
        cipher_aes = AES.new(fileKey, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        # if we want to write to another file
        if file_out != '':
            with open(self.clientAddress + '/' + file_out, 'wb') as f:
                [f.write(x)
                 for x in (salt, keyTag, keyNonce, enc_file_key, cipher_aes.nonce, tag, ciphertext)]
        return salt + keyTag + keyNonce + enc_file_key + cipher_aes.nonce + tag + ciphertext

    def decryptFile(self, path, data=None):
        path = self.clientAddress + '/' + path

        # parse a given file
        if data == None:
            file_in = open(path, 'rb')
            salt, keyTag, keyNonce, enc_file_key, nonce, tag, ciphertext = \
                [file_in.read(x)
                for x in (16, 16, 16, 16, 16, 16, -1)]  # (keyTag, keyNonce, key, nonce, tag, ciphertext)
            file_in.close()
        # decrypt payload into a file
        else:
            salt, keyTag, keyNonce, enc_file_key, nonce, tag = \
                [data[x:x+16] for x in (0, 16, 32, 48, 64, 80)]
            ciphertext = data[96:]

        masterFile = scrypt(self.password.encode('utf-8'),
                        salt, 16, N=2**20, r=8, p=1)
        # decrypt the session key with the public RSA key
        cipher_aes = AES.new(masterFile, AES.MODE_GCM, keyNonce)
        session_key = cipher_aes.decrypt_and_verify(enc_file_key, keyTag)

        # decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        with open(path, 'wb') as f:
            f.write(data)

    def writeMsg(self, msg):
        self.networkRef.send_msg('server', msg)

    def readMsg(self):
        return self.networkRef.receive_msg()

    def incNonce(self):
        self.msgNonce = self.msgNonce[:8] + (int.from_bytes(self.msgNonce[8:], 'big') + 1).to_bytes(8, 'big')

    def clearMessages(self):
        self.networkRef.clear_msgs()

    def endSession(self):
        print("ending session")
        self.writeMsg(self.encMsg("end_session"))
        self.clearMessages()
        print("session over")


def main(newClient, client, network, serverRSA):
    c = Client(client, network, serverRSA)
    try:
        c.loadRSAKeys()
        c.initializeSession(newClient)
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
                    data = c.processResp(c.readMsg())
                    with open(c.clientAddress + '/' + msg[4:], 'wb') as f:
                        f.write(data)
                    c.decryptFile(msg[4:])
                else:
                    c.writeMsg(c.encMsg(msg))
            # wait for response from server
            if msg[:3] == 'dnl':
                msg = msg[4:] + ' downloaded'
            else:
                msg = c.processResp(c.readMsg()).decode('utf-8')
            # print server response
            print(msg)
    finally:
        pass


try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hNc:n:s:', longopts=['help', 'newuser', 'client', 'network', 'serverRSA'])
except getopt.GetoptError:
	print('Usage: python client.py -h)')
	sys.exit(1)

newUser = False
client = None
network = None
serverRSA = None

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python network.py -h <help> -N <new user> -c path_to_client_dir -n path_to_network_dir -s path_to_server_public_RSA')
        print('All args are optional. Note that if client and server are left to default, the server public RSA key must be in the client directory')
        sys.exit(0)
    elif opt == '-N' or opt == '--newuser':
        newUser = True
    elif opt == '-c' or opt == '--client':
        client = arg
    elif opt == '-n' or opt == '--network':
        network = arg
    elif opt == '-s' or opt == '--serverRSA':
        serverRSA = arg

main(newUser, client, network, serverRSA)