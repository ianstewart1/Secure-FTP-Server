
import os
import sys
import getopt
import time

class Client:
    def __init__(self):
        with open("config/config.txt", 'r') as c:
            self.clientAddress = c.readline().split('=')[1]
            if (self.clientAddress[-1] == '\n'):
                self.clientAddress = self.clientAddress[:-1]
            self.serverAddress = c.readline().split('=')[1]
            if (self.serverAddress[-1] == '\n'):
                self.serverAddress = self.serverAddress[:-1]
        self.lastMsg = 0

    def initSession(self):
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
            # here is where user will send commands to server in the future (will require some parsing, yuck!)
            msg = input('Msg: ')
        c.writeMsg(msg)
        # wait for response from server
        response = False
        while (not response):
            msg = c.readMsg()
            if msg != '':
                response = True
        # print server response
        print(f'Response: {msg}')
        time.sleep(0.5)

main()