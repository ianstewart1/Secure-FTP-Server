
import os
import sys
import getopt
import time

class Network:

    def __init__(self, netAddress):
        if netAddress == None:
            if os.path.exists(os.getcwd().split('src')[0] + 'network') == False:
                os.mkdir(os.getcwd().split('src')[0] + 'network')
            netAddress = os.getcwd().split('src')[0] + 'network'
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
            dst = msgs[-1].split('--')[2]
            src = msgs[-1].split('--')[1]
            if dst not in self.addressList:
                os.remove(self.networkAddress + '/' + src + '/OUT/' + msgs[-1])
            else:
                with open(self.networkAddress + '/' + src + '/OUT/' + msgs[-1], 'rb') as f:
                    msg = f.read()
                self.lastRead[src] += 1
                return src, dst, msg
        return '', '', ''

    def writeMsg(self, src, dst, msg):
        msgs = sorted(os.listdir(self.networkAddress + '/' + dst + '/IN'))
        if len(msgs) > 0:
            # increment message number
            next_msg = (int.from_bytes(bytes.fromhex(msgs[-1].split('--')[0]), byteorder='big') + 1).to_bytes(2, byteorder='big').hex()
        else:
            next_msg = '0000'
        with open(self.networkAddress + '/' + dst + '/IN/' + next_msg + "--" + src, 'wb') as f:
            f.write(msg)


def main(network):
    n = Network(network)
    n.clearDir()
    print('Running')
    while True:
        n.getAddresses()
        for addr in n.addressList:
            src, dst, msg = n.readMsg(addr)
            if (dst != '' and msg != ''):
                n.writeMsg(src, dst, msg)
        time.sleep(0.2)

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hn:', longopts=['help', 'network'])
except getopt.GetoptError:
	print('Usage: python network.py -h)')
	sys.exit(1)

network = None

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python network.py -h <help> -n path_to_network_dir')
        print('All args are optional')
        sys.exit(0)
    elif opt == '-n' or opt == '--network':
        network = arg

main(network)
