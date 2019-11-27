
import os
import sys
import getopt
import time

class Client:
    def __init__(self):
        self.clientAddress = ''
        self.serverAddress = ''

    def createDirectory(self, addrDir):
        if not os.path.exists(addrDir):
            os.mkdir(addrDir)
        if not os.path.exists(addrDir + '/IN'):
            os.mkdir(addrDir + '/IN')
        if not os.path.exists(addrDir + '/OUT'):
            os.mkdir(addrDir + '/OUT')

    def canAccessDir(self, addrDir):
        return os.access(addrDir, os.F_OK)
