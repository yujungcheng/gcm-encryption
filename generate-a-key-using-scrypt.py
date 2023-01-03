#!/usr/bin/env python3

from Crypto.Protocol.KDF import scrypt

salt = b'\xfd\xde\xee\x19zx:\x99\xd1\x17N\xc6\xf2$h\xe7\xc9\xf9x\xb0\xe4\x1e\x9e\xd0\x92\xe36W\xf6\xb9\xaaL'
password = 'mypassword123'

key = scrypt(password, salt, key_len=32, N=2**17, r=8, p=1)

print(key)