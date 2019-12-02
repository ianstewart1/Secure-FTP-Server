
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

    def initSession(self):
        pass

    def writeMsg(self, msg):
        pass


def main():
    c = Client()
    # set up session keys and establish secure connection here
    c.initSession()
    while True:
        # send message
        msg = ''
        while msg == '':
            # here is where user will send commands to server in the future (will require some parsing)
            msg = input('Msg: ')
        c.writeMsg(msg)
        # wait for response
        # rinse, repeat
        pass

main()