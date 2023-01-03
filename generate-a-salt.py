#!/usr/bin/env python3

from Crypto.Random import get_random_bytes
salt = get_random_bytes(32)

print(salt)
