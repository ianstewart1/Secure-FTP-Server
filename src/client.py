
import os
import sys
import getopt
import time

class Client:
    def __init__(self):
        with open("config.txt", 'r') as c:
            self.clientAddress = c.readline().split('=')[1]
            if (self.clientAddress[-1] == '\n'):
                self.clientAddress = self.clientAddress[:-1]
            self.serverAddress = c.readline().split('=')[1]

    def createDirectory(self, addrDir):
        if not os.path.exists(addrDir):
            os.mkdir(addrDir)
        if not os.path.exists(addrDir + '/IN'):
            os.mkdir(addrDir + '/IN')
        if not os.path.exists(addrDir + '/OUT'):
            os.mkdir(addrDir + '/OUT')

    def canAccessDir(self, addrDir):
        return os.access(addrDir, os.F_OK)

    def initSession(self):
        pass

    def sendMsg(self):
        pass


def main():
    a = Client()

main()