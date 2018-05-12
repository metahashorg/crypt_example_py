#!/usr/bin/python3
# coding: utf-8

import os
import hashlib
import subprocess

FNULL = open(os.devnull, 'w')

if __name__ == "__main__":
    print("Generating private key")

    result = subprocess.call("openssl ecparam -genkey -name secp256k1 -out mh.pem",
                             shell=True, stdout=FNULL, stderr=subprocess.STDOUT)

    if result == 0:
        print("Done")
    else:
        print("Something went wrong, check your openssl installation")
        exit()

    print("Generating public key")
    result = subprocess.call("openssl ec -in mh.pem -pubout -outform DER|tail -c 65|xxd -p -c 65 > mh_addr.pub",
                             shell=True, stdout=FNULL, stderr=subprocess.STDOUT)

    if result == 0:
        print("Done")
    else:
        print("Something went wrong, check your openssl installation")
        exit()

    print("Generating Metahash Address")

    with open("mh_addr.pub", 'br') as f:
        pub_key = f.read()

        h = hashlib.new('sha256')
        h.update(pub_key)
        resulrt_sha256 = h.hexdigest()

        h = hashlib.new('rmd160')
        h.update(resulrt_sha256.encode('utf-8'))
        resulrt_rmd160 = '00' + h.hexdigest()

        h = hashlib.new('sha256')
        h.update(resulrt_rmd160.encode('utf-8'))
        resulrt_sha256rmd = h.hexdigest()

        h = hashlib.new('sha256')
        h.update(resulrt_sha256rmd.encode('utf-8'))
        resulrt_sha256rmd_again = h.hexdigest()

        first4_resulrt_sha256rmd_again = resulrt_sha256rmd_again[:4]

        address = '0x' + resulrt_rmd160 + first4_resulrt_sha256rmd_again

        print("Your Metahash address is %s" % address)

        text_file = open("mh_address.txt", "w")
        text_file.write(address)
        text_file.close()