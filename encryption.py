#!/usr/bin/env python3

import sys
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

BUFFER_SIZE = 1024*1024

password = str(sys.argv[1])
input_filename = str(sys.argv[2]) 
output_filename = input_filename + '.encrypted'

salt = get_random_bytes(32)  # generate a salt
key = scrypt(password, salt, key_len=32, N=2**17, r=8, p=1)

with open(output_filename, 'wb') as file_out:
    file_out.write(salt)

    cipher = AES.new(key, AES.MODE_GCM)
    file_out.write(cipher.nonce)

    with open(input_filename, 'rb') as file_in:
        data = file_in.read(BUFFER_SIZE)
        while len(data) != 0:
            encrypted_data = cipher.encrypt(data)
            file_out.write(encrypted_data)
            data = file_in.read(BUFFER_SIZE)
        
    tag = cipher.digest()
    file_out.write(tag)    