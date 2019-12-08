
import os
import sys
import getopt
import time

class Network:

    def __init__(self, netAddress=os.getcwd()):
        if 'src' in netAddress:
            if os.path.exists(netAddress.split('src')[0] + 'network') == False:
                os.mkdir(netAddress.split('src')[0] + 'network')
            netAddress = netAddress.split('src')[0] + 'network'
        self.networkAddress = netAddress
        self.addressList = []
        self.lastRead = {}

    def getAddresses(self):
        for d in os.listdir(self.networkAddress):
            if d not in self.addressList:
                self.lastRead[d] = -1
                self.addressList.append(d)

    def clearDir(self):
        for addr in os.listdir(self.networkAddress):
            for msg in os.listdir(self.networkAddress + '/' + addr + '/IN'): os.remove(self.networkAddress + '/' + addr + '/IN/' + msg)
            for msg in os.listdir(self.networkAddress + '/' + addr + '/OUT'): os.remove(self.networkAddress + '/' + addr + '/OUT/' + msg)

    def readMsg(self, src):
        msgs = sorted(os.listdir(self.networkAddress + '/' + src + '/OUT'))
        if len(msgs) <= self.lastRead[src]:
            self.lastRead[src] = -1
        elif len(msgs) - 1 > self.lastRead[src]:
            dst = msgs[-1].split('--')[1]
            if dst not in self.addressList:
                os.remove(self.networkAddress + '/' + src + '/OUT/' + msgs[-1])
            else:
                with open(self.networkAddress + '/' + src + '/OUT/' + msgs[-1], 'rb') as f:
                    msg = f.read()
                self.lastRead[src] += 1
                return dst, msg
        return '', ''

    def writeMsg(self, dst, msg):
        msgs = sorted(os.listdir(self.networkAddress + '/' + dst + '/IN'))
        if len(msgs) > 0:
            next_msg = (int.from_bytes(bytes.fromhex(msgs[-1]), byteorder='big') + 1).to_bytes(2, byteorder='big').hex()
        else:
            next_msg = '0000'
        with open(self.networkAddress + '/' + dst + '/IN/' + next_msg, 'wb') as f:
            f.write(msg)


def main():
    n = Network()
    n.clearDir()
    cycles = 0
    while True:
        print('Running' + '.'*(cycles%4) + ' '*4, end='\r')
        time.sleep(0.5)
        n.getAddresses()
        for addr in n.addressList:
            dst, msg = n.readMsg(addr)
            if (dst != '' and msg != ''):
                n.writeMsg(dst, msg)
        cycles += 1

main()
