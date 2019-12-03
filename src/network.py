
import os
import sys
import getopt
import time

class Network:
    def __init__(self, client=os.getcwd(), server=os.getcwd()):
        self.clientAddress = client.split('src')[0] + 'client'
        self.serverAddress = server.split('src')[0] + 'server'

    def createDirectory(self, addrDir):
        if not os.path.exists(addrDir):
            os.mkdir(addrDir)
        if not os.path.exists(addrDir + '/IN'):
            os.mkdir(addrDir + '/IN')
        if not os.path.exists(addrDir + '/OUT'):
            os.mkdir(addrDir + '/OUT')

    def transferToClient(self, msg):
        with open(self.serverAddress + '/OUT/' + msg, 'r') as m:
            txt = m.read()
        with open(self.clientAddress + '/IN/' + msg, 'w') as m:
            m.write(txt)

    def transferToServer(self, msg):
        with open(self.clientAddress + '/OUT/' + msg, 'r') as m:
            txt = m.read()
        with open(self.serverAddress + '/IN/' + msg, 'w') as m:
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
    cycles = 0
    while True:
        print('Running' + '.'*(cycles%4) + ' '*4, end='\r')
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
        cycles += 1

main()
