
import os
import sys
import getopt
import time

class Server:
    def __init__(self, server=os.getcwd()):
        self.serverAddress = server.split('src')[0] + 'server'
        self.lastMsg = 0

    def initSession(self):
        pass

    def writeMsg(self, msg):
        msgs = sorted(os.listdir(self.serverAddress + '/OUT/'))
        if len(msgs) > 0:
            nextMsg = (int.from_bytes(bytes.fromhex(msgs[-1]), 'big') + 1).to_bytes(2, 'big').hex()
        else:
            nextMsg = '0000'
        with open(self.serverAddress + '/OUT/' + nextMsg, 'w') as m:
            m.write(msg)

    def readMsg(self):
        msgs = sorted(os.listdir(self.serverAddress + '/IN'))
        if len(msgs) > self.lastMsg:
            self.lastMsg += 1
            with open(self.serverAddress + '/IN/' + msgs[-1], 'r') as m:
                return m.read()
        return ''


def main():
    s = Server()
    # set up session keys and establish secure connection here
    s.initSession()
    while True:
        # wait for message from client, eventually going to need command parsing (yuck!)
        response = False
        cycles = 0
        while (not response):
            print('Waiting' + '.'*(cycles%4) + ' '*4, end='\r')
            msg = s.readMsg()
            if msg != '':
                response = True
            time.sleep(0.5)
            cycles += 1
        # print client message (for debugging)
        print(f"Client command: {msg}{' '*20}")
        # send response to client (this will be other stuff eventually)
        msg = 'Message received.'
        s.writeMsg(msg)
        time.sleep(0.5)

main()