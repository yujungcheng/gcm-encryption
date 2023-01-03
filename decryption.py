#!/usr/bin/env python3

import os
import sys

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

BUFFER_SIZE = 1024*1024
SALT_SIZE = 32

password = str(sys.argv[1])
input_filename = str(sys.argv[2])
output_filename = str(sys.argv[3])

with open(input_filename, 'rb') as file_in:
    salt = file_in.read(SALT_SIZE)
    key = scrypt(password, salt, key_len=32, N=2**17, r=8, p=1)

    nonce = file_in.read(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    filesize = os.path.getsize(input_filename)
    encrypted_data_size = filesize - 32 - 16 - 16  # total size - salt - nonce - tag = encrypted data size

    with open(output_filename, 'wb') as file_out:
        for _ in range(int(encrypted_data_size / BUFFER_SIZE)):
            data = file_in.read(BUFFER_SIZE)
            decrypted_data = cipher.decrypt(data)
            file_out.write(decrypted_data)
        data = file_in.read(int(encrypted_data_size % BUFFER_SIZE))
        decrypted_data = cipher.decrypt(data)
        file_out.write(decrypted_data)

    tag =  file_in.read(16)
    try:
        cipher.verify(tag)
    except ValueError as e:
        file_in.close()
        file_out.close()
        os.remove(output_filename)
        raise e