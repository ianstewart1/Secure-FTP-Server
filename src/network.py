
import os
import sys
import getopt
import time

class Network:
    def __init__(self):
        with open("config/config.txt", 'r') as c:
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

    def transferToClient(self, msg):
        with open(self.serverAddress + '/OUT/' + msg, 'rb') as m:
            txt = m.read()
        with open(self.clientAddress + '/IN/' + msg, 'wb') as m:
            m.write(txt)

    def transferToServer(self, msg):
        with open(self.clientAddress + '/OUT/' + msg, 'rb') as m:
            txt = m.read()
        with open(self.serverAddress + '/IN/' + msg, 'wb') as m:
            m.write(txt)
        
    def clearMsgs(self, address):
        for msg in os.listdir(address + '/IN'): os.remove(address + '/IN/' + msg)
        for msg in os.listdir(address + '/OUT'): os.remove(address + '/OUT/' + msg)


def main():
    n = Network()
    # make sure each party has the necessary directories at their addresses
    n.createDirectory(n.clientAddress)
    n.createDirectory(n.serverAddress)
    # clear pre-existing messages out (fresh session!)
    n.clearMsgs(n.clientAddress)
    n.clearMsgs(n.serverAddress)
    # message counter (to check what has already been sent)
    clientC, serverC = 0, 0
    while True:
        time.sleep(0.5)
        # client to server
        msgs = sorted(os.listdir(n.clientAddress + '/OUT'))
        if clientC < len(msgs):
            n.transferToServer(msgs[-1])
            clientC += 1
        # server to client
        msgs = sorted(os.listdir(n.serverAddress + '/OUT'))
        if serverC < len(msgs):
            n.transferToClient(msgs[-1])
            serverC += 1

main()
