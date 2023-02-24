###### [challenge and solutions](https://github.com/dicegang/dicectf-2023-challenges/tree/main/crypto/provably-secure)

The challenge generates 2 public keys and corresponding private keys. It shares the public number `n`. The public exponent `e` is always 65537. Using these, we can generate the public number:

```python
    pk0 = rsa.RSAPublicNumbers(n=n0, e=65537).public_key()
    pk1 = rsa.RSAPublicNumbers(n=n1, e=65537).public_key()
```

Once we have the public keys, we can encrypt a known plaintext using the public keys.

The challenge takes 2 messages from the user and it selects and encrypts one of the messages depending on the value of `m_bit`. 

```python
 msg = m0 if m_bit == 0 else m1
 ct = encrypt(pk0, pk1, msg)
 seen_ct.add(ct)
```

The challenge first xor the selected message with a random string and then encrypt the random string and the xored string. The encryption message is formed by concatenating the encrypted random string and the encrypted  xored string.

```python
def encrypt(pk0, pk1, msg):
    r = urandom(16)
    r_prime = strxor(r, msg)
    ct0 = pk0.encrypt(r, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
    ct1 = pk1.encrypt(r_prime, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                         algorithm=hashes.SHA256(), label=None))
    return ct0.hex() + ct1.hex()
```

The solution is to determine which given message is encrypted in turn find out the value of `m_bit`. 

In the solution, I created 2 new encryption strings from the encrypted text by modifying half of it with the know plaintext encrypted string (known as `enc_0` and `enc_1`).

```python
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
        
```

The challenge will decrypt the `enc_0` and `enc_1` and xoring the decryption the strings will give back the message that was encrypted in the first place. 


