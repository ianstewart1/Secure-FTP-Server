import os, time


class network_interface:
    own_addr = None
    net_path = None
    last_read = -1
	
    def __init__(self, path, addr):
        self.net_path = path
        self.own_addr = '/' + addr
        
        addr_dir = self.net_path + self.own_addr
        if not os.path.exists(addr_dir):
            os.mkdir(addr_dir)
            os.mkdir(addr_dir + '/IN')
            os.mkdir(addr_dir + '/OUT')
        self.clear_msgs()
	
    def send_msg(self, dst, msg):

        out_dir = self.net_path + self.own_addr + '/OUT'
        msgs = sorted(os.listdir(out_dir))

        if len(msgs) > 0:
            last_msg = msgs[-1].split('--')[0]
            next_msg = (int.from_bytes(bytes.fromhex(last_msg), byteorder='big') + 1).to_bytes(2, byteorder='big').hex()
        else:
            next_msg = '0000'
		
        next_msg += '--' + self.own_addr[1:] + '--' + dst
        with open(out_dir + '/' + next_msg, 'wb') as f: f.write(msg)

    def receive_msg(self):

        in_dir = self.net_path + self.own_addr + '/IN'

        status = False
        msg = b''

        while True:
            msgs = sorted(os.listdir(in_dir))
            if len(msgs) - 1 > self.last_read: 
                with open(in_dir + '/' + msgs[self.last_read + 1], 'rb') as f: msg = f.read()
                status = True
                src = msgs[self.last_read + 1].split('--')[1]
                self.last_read += 1

            if status: 
                if src != 'server':
                    return msg, src
                return msg
            else: time.sleep(0.5)

    def clear_msgs(self):
        addr_dir = self.net_path + self.own_addr
        for msg in os.listdir(addr_dir + '/IN'):
            os.remove(addr_dir + '/IN/' + msg)
        # os.remove(addr_dir + '/IN')
        for msg in os.listdir(addr_dir + '/OUT'):
            os.remove(addr_dir + '/OUT/' + msg)
        # os.remove(addr_dir + '/OUT')
