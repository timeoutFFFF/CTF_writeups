
import binascii
from pwn import *
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import sys
import os
from Crypto.Util.strxor import strxor

def my_encrypt(pk, msg):
    ct = pk.encrypt(msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    return ct.hex()


def get_public_keys():
    pk0 = None
    pk1 = None

    r = p.recvuntil(b"Action:")
    if b"pk0" in r:
        lines = r.splitlines()
    for line in lines:
        if b"pk0" in line:
            pk0 = line.split(b"= ")[1]
        elif b"pk1" in line:
            pk1 = line.split(b"= ")[1]
    if pk0 == None or pk1 == None:
        print(f"pk0 = {pk0}\npk1 = {pk1}")
        sys.exit(1)

    return pk0, pk1

def send_mbit(mbit):
    # choice 0
    p.sendline(b"0")
    p.sendlineafter(b"guess: ", mbit)


def encrypt_msg(msg0=b"A"*16, msg1=b"B"*16):
    # choice 1
    p.sendline(b"1")
    p.sendlineafter(b"m0 (16 byte hexstring): ", msg0.hex())
    p.sendlineafter(b"m1 (16 byte hexstring): ", msg1.hex())

    encrypt = p.recvuntil(b"Action: ")
    return encrypt.splitlines()[0]

def decrypt_msg(msg):
    # choice 2
    p.sendline(b"2")
    p.sendlineafter(b"hexstring): ", msg)
    plaintext =  p.recvuntil(b"Action: ").splitlines()[0]
    return plaintext

p = process("server.py")
#context.log_level = 'debug'
for i in range(128):

    # get public keys
    n0, n1 = get_public_keys()
    n0, n1 = int(n0), int(n1)
    pk0 = rsa.RSAPublicNumbers(n=n0, e=65537).public_key()
    pk1 = rsa.RSAPublicNumbers(n=n1, e=65537).public_key()
    
    # find m_bits
    mbit = None

    msg0 = b"A" * 16
    msg1 = b"B" * 16
    while True:
        # encrypt message
        enc  = encrypt_msg(msg0, msg1)
 
        # we know public key so encrypt known 16-bytes string
        my_msg = b"0"*16

        # encrypt the message with pk1
        pk1_encrypt = my_encrypt(pk1, my_msg)
        # encrypt the message with pk0
        pk0_encrypt = my_encrypt(pk0, my_msg)
        
        len_enc = len(enc) // 2       
        enc_0 =  str.encode(pk0_encrypt) + enc[len_enc:]
        enc_1 = enc[:len_enc] + str.encode(pk1_encrypt)
        
        p0 = binascii.unhexlify(decrypt_msg(enc_0))
        p1 = binascii.unhexlify(decrypt_msg(enc_1))
        
        msg = strxor(p0, p1)
        print(f" msg = {msg}")
        if msg == msg0:
            mbit = b"0"
        elif msg == msg1:
            mbit = b"1"
        if mbit:
            send_mbit(mbit)
            break
# should prin the flag
print(p.recvline())
print(p.recvline())

