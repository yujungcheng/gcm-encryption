#!/usr/bin/env python3
import io

my_bytes_object = b'\xfd\xde\xee\x19zx:\x99\xd1\x17N\xc6\xf2$h\xe7\xc9\xf9x\xb0\xe4\x1e\x9e\xd0\x92\xe36W\xf6\xb9\xaaL'
file_object = io.BytesIO(my_bytes_object)
print(file_object.read())


my_string_to_encrypt = 'My string to be encrypted!'
my_file = io.BytesIO(my_string_to_encrypt.encode())
print(my_file.read().decode())