#!/usr/bin/python3
# coding: utf-8

import binascii
import hashlib
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
except ImportError:
    print("Something went wrong, check your cryptography module installation")

if __name__ == '__main__':
    print("Step 1. Generate rpivate and public keys. Take part of the public "
          "key that equals to 65 bytes.")
    key = ec.generate_private_key(ec.SECP256K1(), default_backend())

    key_pem = key.private_bytes(encoding=Encoding.PEM,
                                format=PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=NoEncryption())

    pub_key = key.public_key()
    pub_key_der = pub_key.public_bytes(encoding=Encoding.DER,
                                format=PublicFormat.SubjectPublicKeyInfo)
    pub_key_pem = pub_key.public_bytes(encoding=Encoding.PEM,
                                format=PublicFormat.SubjectPublicKeyInfo)

    pub_key_der_65 = pub_key_der[:65]
    pub_key = binascii.b2a_hex(pub_key_der_65)
    print("Done")

    print("Step 2. Perform SHA-256 hash on the public key.")
    h = hashlib.new('sha256')
    t = binascii.a2b_hex(pub_key)
    h.update(binascii.a2b_hex(pub_key))
    resulrt_sha256 = h.hexdigest()
    print("Done")

    print("Step 3. Perform RIPEMD-160 hash on the result of previous step.")
    h = hashlib.new('rmd160')
    h.update(binascii.a2b_hex(resulrt_sha256.encode('utf-8')))
    resulrt_rmd160 = '00' + h.hexdigest()
    print("Done")

    print("Step 4. SHA-256 hash is calculated on the result of previous step.")
    h = hashlib.new('sha256')
    h.update(binascii.a2b_hex(resulrt_rmd160.encode('utf-8')))
    resulrt_sha256rmd = h.hexdigest()
    print("Done")

    print("Step 5. Another SHA-256 hash performed on value from Step 4 and "
          "save first 4 bytes.")
    h = hashlib.new('sha256')
    h.update(binascii.a2b_hex(resulrt_sha256rmd.encode('utf-8')))
    resulrt_sha256rmd_again = h.hexdigest()
    first4_resulrt_sha256rmd_again = resulrt_sha256rmd_again[:8]
    print("Done")

    print("Step 6. These 4 bytes from last step added to RIPEMD-160 hash with "
          "prefix 0x. ")
    address = '0x' + resulrt_rmd160 + first4_resulrt_sha256rmd_again

    print("Your Metahash address is %s" % address)

    text_file = open("mh_address.txt", "w")
    text_file.write(address)
    text_file.close()

    text_file = open("mh_public.pub", "w")
    text_file.write(pub_key.decode("utf-8"))
    text_file.close()

    text_file = open("mh_private.pem", "w")
    text_file.write(key_pem.decode("utf-8"))
    text_file.close()