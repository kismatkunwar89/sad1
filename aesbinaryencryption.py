import sys
import io
import hashlib
from Crypto.Cipher import AES

def pad(s):
    padding = AES.block_size - len(s) % AES.block_size
    return s + bytes([padding]) * padding

def aesenc(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

try:
    with open(sys.argv[1], "rb") as f:
        plaintext = f.read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()
    
key = hashlib.sha256(b"Your Key").digest()
ciphertext = aesenc(plaintext, key)

print('unsigned char key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in key) + ' };')
print('unsigned char payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
