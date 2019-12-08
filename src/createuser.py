import os
import getpass
from Crypto.Hash import SHA256

username = input("Enter a username: ")
password = getpass.getpass("Enter a password: ")

password = password.encode('utf-8')
h = SHA256.new(data=password)
hashed_pass = h.digest()
userfolder = os.getcwd().split('src')[0] + 'server/USERS/' + username
os.mkdir(userfolder)
os.mkdir(userfolder + "/root")

with open(userfolder + "/.hash_check.hash", "wb") as f:
    f.write(hashed_pass)