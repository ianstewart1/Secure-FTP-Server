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
            serverRSA = self.clientAddress + '/serverRSApublic.pem'
        if not os.path.exists(serverRSA):
            serverRSA = os.getcwd() + "/example_server_keys/serverRSApublic.pem"
        self.serverRSApublic = serverRSA
        # used for keeping track of new messages
        self.lastMsg = 0
        self.msgNonce = None
        # set after initSession - session key
        self.AESKey = None
        # user params
        self.login()
        # network connection
        if network == None:
            network = os.getcwd().split('src')[0] + 'network'
            if not os.path.exists(network):
                os.mkdir(network)
        self.networkPath = network
        self.networkRef = network_interface(self.networkPath, self.username)

    def initializeSession(self, newUser):
        print('Establishing session...')
        # get a random bytestring to use as key
        self.AESKey = get_random_bytes(16)

        # encrypt the data with the AES session key
        if not newUser:
            plaintext = "login:".encode('utf-8') + self.username.encode(
                'utf-8') + ':'.encode('utf-8') + self.password.encode('utf-8')
        else:
            plaintext = "newusr:".encode('utf-8') + self.username.encode(
                'utf-8') + ':'.encode('utf-8') + self.password.encode('utf-8')

        # initilize AES nonce (replay protection)
        # first 8 bytes are randomly generated for each session, last 8 bytes are a counter
        zero = 0
        randomBytes = get_random_bytes(8)
        self.msgNonce = randomBytes + zero.to_bytes(8, 'big')
        # encrypt plaintext message and prepend with cipher tag
        messageContent = self.encMsg(plaintext)

        # Encrypt the session key with the server's public RSA key
        cipher_rsa = PKCS1_OAEP.new(self.serverRSApublic)
        encAESandRandom = cipher_rsa.encrypt(self.AESKey + randomBytes)

        # send first message
        self.writeMsg(encAESandRandom + messageContent)

        # receive and Process Server Response
        resp = self.processResp(self.readMsg())

        # check if the server received and properly decoded the message
        if resp.decode('utf-8') != self.username:
            print('Communication error, quitting')
            self.endSession()
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
            return plain
        except ValueError:
            print('MAC verification failed, ending session...')
            exit(1)

    def loadRSAKeys(self):
        # called during session intialization to load the server's public RSA key for use in the first message to server
        if not os.path.exists(self.serverRSApublic):
            self.serverRSApublic = os.getcwd() + '/example_server_keys/serverRSApublic.pem'
        with open(self.serverRSApublic, 'rb') as f:
            self.serverRSApublic = RSA.import_key(f.read())

    def login(self):
        # called at the start of a session
        userN = ''
        passwrd = ''
        fpasswrd = ''
        while userN == '' or passwrd == '' or fpasswrd == '':
            userN = input("Enter your username: ")
            passwrd = getpass.getpass("Enter your password: ")
            fpasswrd = getpass.getpass("Enter your file encryption/decryption password: ")
        self.username = userN
        self.password = passwrd
        self.filePassword = fpasswrd

    def encryptFile(self, file_in, file_out=''):
        try:
            # because server should never have access to plaintext file data
            with open(self.clientAddress + '/' + file_in, 'rb') as f:
                data = f.read()
            
            # derive file key from user password
            salt = get_random_bytes(16)
            fileKey = scrypt(self.filePassword.encode('utf-8'), salt, 16, N=2**20, r=8, p=1)

            # encrypt the data with the file key
            cipher_aes = AES.new(fileKey, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data)

            # if we want to write to another file
            if file_out != '':
                with open(self.clientAddress + '/' + file_out, 'wb') as f:
                    [f.write(x)
                    for x in (salt, cipher_aes.nonce, tag, ciphertext)]
            return salt + cipher_aes.nonce + tag + ciphertext
        except:
            print("Encryption Failed")
            return None

    def decryptFile(self, path, data=None):
        path = self.clientAddress + '/' + path

        # parse a given file if data is empty
        if data == None:
            file_in = open(path, 'rb')
            salt, nonce, tag, ciphertext = \
                [file_in.read(x)
                 for x in (16, 16, 16, -1)]
            file_in.close()

        # read in data if given
        else:
            salt, nonce, tag, ciphertext = \
                [data[x:x+16]
                 for x in (0, 16, 32, -1)]
            ciphertext = data[48:]

        # Generate file key from given filePassword
        fileKey = scrypt(self.filePassword.encode('utf-8'),
                        salt, 16, N=2**20, r=8, p=1)

        # Decrypt the data with the file key
        cipher_aes = AES.new(fileKey, AES.MODE_GCM, nonce)
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
        print("Session over")
        sys.exit(0)


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
                    if data!=None:
                        c.writeMsg(c.encMsg(msg, data))
                    else:
                        msg = ''
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
            if msg == "end_session":
                print("Session Ended")
                sys.exit(0)
            # print server response
            print(msg)
    except:
        c.writeMsg(c.encMsg("end_session"))


try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='huc:n:s:', longopts=['help', 'newuser', 'client', 'network', 'serverRSA'])
except getopt.GetoptError:
	print('Usage: python client.py -h)')
	sys.exit(1)

newUser = False
client = None
network = None
serverRSA = None

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python network.py -h <help> -u <new user> -c path_to_client_dir -n path_to_network_dir -s path_to_server_public_RSA_dir')
        print('All args are optional unless you are a new user and must use -N')
        sys.exit(0)
    elif opt == '-u' or opt == '--newuser':
        newUser = True
    elif opt == '-c' or opt == '--client':
        client = arg
    elif opt == '-n' or opt == '--network':
        network = arg
    elif opt == '-r' or opt == '--serverRSA':
        serverRSA = arg

main(newUser, client, network, serverRSA)
