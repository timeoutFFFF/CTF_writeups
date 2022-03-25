
from pwn import *
import os

#context.log_level = 'debug'

def trailing(x):
    a = 0
    for _ in range(15):
        if x & 1:
            break
        x >>= 1
        a += 1
    #print(a)
    return a

def cal_hash(s, k1, k2):
    result = ""
    for x in s:
        for y in s:
            result += hex(trailing((k1 ^ x) * (k2 ^ y)))[2:]

    return result


prog = ["python3", "main.py"]

def start():
    if args.REMOTE:
        return remote("", 8181)
    else:
        return process(prog)


def get_hash1(p, val):
    p.sendafter(")\n", val)
    hash_1 = p.recvuntil("\n").strip(b"\n")
    return hash_1.decode()


def get_hash2(p, val):
    p.sendafter("...", val)
    hash_2 = p.recvuntil("\nTime").split(b"\n")[1]
    return hash_2.decode()

def guess_rand1(p, val):
    hash1 = p.sendlineafter("k1:", val)

def bruteforce_hashes(first_number):
    result = {}
    for i in range(256):
        for j in range(256):
            hash_val = cal_hash(first_number, i , j)
            guess_val = result.get(hash_val, set())
            guess_val.add(i)
            guess_val.add(j)
            result[hash_val] = guess_val
    #print(result)
    return result

def main():
    # start the process

    first_number = bytes(range(16))
    #second_number = bytes(range(0x10, 0xff, 0x10)).ljust(16, b'\xff')

    bruteforce_first_number  = bruteforce_hashes(first_number)
    #bruteforce_second_number = bruteforce_hashes(second_number)

    p = start()
    for i in range(100):
        k1 = os.urandom(1)[0]
        k2 = os.urandom(1)[0]
        
        # challenge 1
        hash_1 = get_hash1(p, first_number)
        hash_1_val = bruteforce_first_number[hash_1]
        log.info(f"hash_1: {hash_1} ")

        second_number = bytes(hash_1_val).rjust(16, b"\x00")
        #challenge 2
        hash_2 = get_hash2(p, second_number)
        #hash_2_val = bruteforce_second_number[hash_2]
        log.info(f"hash_2: {hash_2}")

        #log.info(f"hash_1: {hash_1_val}, hash_2: {hash_2_val}")

        for x in hash_1_val:
            for y in hash_1_val:
                 if cal_hash(second_number, x, y) == hash_2:
                     # guess the first number
                     p.sendlineafter("k1:", str(x))

                     # guess the second number
                     p.sendlineafter("k2:", str(y))
                     

    p.interactive()

if __name__ == "__main__":
    main()
