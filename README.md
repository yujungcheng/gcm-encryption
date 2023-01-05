# GCM Encryption

###### tags: `gcm`

A basic understand about GCM mode (Galois Counter Mode) in AES encryption.


#### Key notes
Advanced Encryption Standard (AES) is a fast, secure and very popular block cipher that is commonly used to encrypt electronic data. AES has three different block ciphers: AES-128 (128 bit), AES-192 (192 bit) and AES-256 (256 bit) - each cipher is named after the key length they use for encryption and decryption.

AES supports many different "modes". Modes are the internal algorithm used to encrypt data; each mode can potentially have different inputs and outputs but they always have a single input for data to encrypt and a single output for encrypted data along with an input key.

GCM is a mode of AES that uses the CTR (counter) mode to encrypt data and uses Galois mode for authentication. Aside from the CTR mode which is used to encrypt the data, Galois mode authentication allows us to check at the end of decryption that the message has not been tampered with. GCM is well known for its speed and that it's a mode that it's patent-free.

Galois/Counter Mode (GCM) is a mode of operation for symmetric-key cryptographic block ciphers which is widely adopted for its performance.

CTR mode turns a block cipher into a stream cipher. It generates the next keystream block by encrypting successive values of a "counter". The counter can be any function which produces a sequence which is guaranteed not to repeat for a long time, although an actual increment-by-one counter is the simplest and most popular.

Nonce is used by authentication protocols to ensure that old communications cannot be reprocessed. Hashing. Proof of work systems use nonce values to vary input to a cryptographic hash function. This helps fulfill arbitrary conditions and provide a desired difficulty.

#### Install
```
ycheng@NUC10:~$ python3 -m pip install pycryptodome
Defaulting to user installation because normal site-packages is not writeable
Collecting pycryptodome
  Downloading pycryptodome-3.16.0-cp35-abi3-manylinux_2_5_x86_64.manylinux1_x86_64.manylinux_2_12_x86_64.manylinux2010_x86_64.whl (2.3 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.3/2.3 MB 6.4 MB/s eta 0:00:00
Installing collected packages: pycryptodome
Successfully installed pycryptodome-3.16.0
```

#### Generate a key
When generating a key from a password, we need to take a string provided by the user and create an appropriately sized byte sequence; the method used must produce the same output for the same inputs. To do this we can use Crypto.Protocol.KDF.scrypt (API reference). scrypt allows us to generate a key of any length by simply passing a password and salt. 

##### Generating a Salt
A salt is random data that is used as an additional input to a one-way function that "hashes" data. 
```
#!/usr/bin/env python3

from Crypto.Random import get_random_bytes
salt = get_random_bytes(32)

print(salt)
```
```
ycheng@NUC10:~/Data/learn/python/gcm-encryption$ ./generate-a-salt.py 
b'\xfd\xde\xee\x19zx:\x99\xd1\x17N\xc6\xf2$h\xe7\xc9\xf9x\xb0\xe4\x1e\x9e\xd0\x92\xe36W\xf6\xb9\xaaL'
```

##### Generating the key using scrypt
```
#!/usr/bin/env python3

from Crypto.Protocol.KDF import scrypt

salt = b'\xfd\xde\xee\x19zx:\x99\xd1\x17N\xc6\xf2$h\xe7\xc9\xf9x\xb0\xe4\x1e\x9e\xd0\x92\xe36W\xf6\xb9\xaaL'
password = 'mypassword123'

key = scrypt(password, salt, key_len=32, N=2**17, r=8, p=1)

print(key)
```
```
ycheng@NUC10:~/Data/learn/python/gcm-encryption$ ./generate-a-key-using-scrypt.py 
b'\xe6N\xba\xc2\x0b\x02q\x800R\xa7\x95\x1c\x96?\xed,\xef\xc8`\xdd\xc7/\xac\xe05\x8d\xf0\x85O3\xe2'
```
As long as passing same salt and password, it generates same key.

#### Source and Storage Planning
Before we begin, we need to do a bit of planning of what is being encrypted (the source) and any transformations required, the inputs and outputs for both encryption and decryption and storing values we need to remember with the encrypted file.

##### Identifying your source and transformations
```
#!/usr/bin/env python3
import io

my_bytes_object = b'\xfd\xde\xee\x19zx:\x99\xd1\x17N\xc6\xf2$h\xe7\xc9\xf9x\xb0\xe4\x1e\x9e\xd0\x92\xe36W\xf6\xb9\xaaL'
file_object = io.BytesIO(my_bytes_object)
print(file_object.read())


my_string_to_encrypt = 'My string to be encrypted!'
my_file = io.BytesIO(my_string_to_encrypt.encode())
print(my_file.read().decode())
```
```
ycheng@NUC10:~/Data/learn/python/gcm-encryption$ ./convert-bytes-object-to-bytesIO.py 
b'\xfd\xde\xee\x19zx:\x99\xd1\x17N\xc6\xf2$h\xe7\xc9\xf9x\xb0\xe4\x1e\x9e\xd0\x92\xe36W\xf6\xb9\xaaL'
My string to be encrypted!
```

##### Encryption planning
![](https://i.imgur.com/HUtBEzE.png)

1. Generate a new salt.
2. Use **scrypt** to convert the salt and password into a key.
3. Open a new file and write the salt out.
    - We write the salt to the output file first as we will need it when decrypting later.
    - Putting it in this file allows us to keep the correct salt with the encrypted data.
    - Putting it at the top of the file means we can easily read it out before decrypting (we know the length as it's always the same).
4. Create a new AES encryption instance using the key.
5. Write the nonce out to the file.
    - The nonce is a random byte sequence generated by the instances of AES and is the start of the counter in CTR mode.
    - This is different so if the same key and file and encrypted together again, the encryption will be different. (**I am not pretty understand this, I think it means this nonce value keep changing through each encryption block.**)
    - Just like the salt, this is also stored at the top of the file so we can read it out again before decrypting to tell the CTR mode where to start counting from.
6. Read some data from the file into a buffer and then give it to the encryption instance.
7. Write the encrypted data to the file.
    - 6 and 7 are repeated over and over again until there is no more data coming from the source file.
    - We read small parts out of the file at a time so we don't have to load the whole file into memory.
8. Write the tag to the output file.
    - This is the authentication **code** produced from the Galois mode authentication.
    - This is used in the decryption phase to identify tampering/corruption.

##### Decryption planning
![](https://i.imgur.com/yhvA2q0.png)

1. Read the salt from the source file.
    - The salt we generated was 32 bytes long, so calling .read(32) will get the salt out of the encrypted file.
2. Use scrypt to convert the salt and password into a key again.
3. Read the nonce from the source file like we did for the salt.
    - AES GCM always generates a nonce that is 16 bytes long, so calling .read(16) will get the nonce out of the encrypted file.
4. Create a new AES decryption instance using the key and the nonce.
5. Read the encrypted file bit-by-bit and decrypt, then output each part to the output file. Leave the tag still in the file (16 bytes also)
    - Just like when we read the file slowly to encrypt
6. Finally, read the tag and verify the decryption.

#### Encryption source code
``` Python 3.10.6

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
```
```
ycheng@NUC10:~/Data/learn/python/gcm-encryption$ dd if=/dev/urandom of=./input_file bs=1024 count=4
4+0 records in
4+0 records out
4096 bytes (4.1 kB, 4.0 KiB) copied, 0.000561881 s, 7.3 MB/s

ycheng@NUC10:~/Data/learn/python/gcm-encryption$ ./encryption.py password123 input_file
ycheng@NUC10:~/Data/learn/python/gcm-encryption$ ls -l ./input_file*
-rw-rw-r-- 1 ycheng ycheng 4096 Jan  3 16:22 ./input_file
-rw-rw-r-- 1 ycheng ycheng 4160 Jan  3 16:50 ./input_file.encrypted
```

#### Decryption source code
``` Python 3.10.6

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
```
```
ycheng@NUC10:~/Data/learn/python/gcm-encryption$ ./decryption.py password123 input_file.encrypted output_file.decrypted
ycheng@NUC10:~/Data/learn/python/gcm-encryption$ ls -l ./output_file.decrypted 
-rw-rw-r-- 1 ycheng ycheng 4096 Jan  3 16:51 ./output_file.decrypted
```
**__NOTE__**: use same "password" to decrypt.
**__NOTE__**: use "diff" or "cmp" to compare files.


#### Terms
The Advanced Encryption Standard (AES), also known by its original name Rijndael, is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001.  
A rainbow table is a precomputed table for caching the output of cryptographic hash functions, usually for cracking password hashes.  


#### Reference
https://nitratine.net/blog/post/python-gcm-encryption-tutorial/  
https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/  
https://en.wikipedia.org/wiki/Galois/Counter_Mode  
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)  
https://asecuritysite.com/encryption/aes_gcm  
https://github.com/wolf43/AES-GCM-example  
https://www.techtarget.com/searchsecurity/definition/nonce  