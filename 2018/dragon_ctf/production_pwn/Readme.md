
#### Challenge link: 
 * https://github.com/j00ru/ctf-tasks/tree/master/Dragon%20CTF%202018/Teaser/Production/task
 
## The challenge description

The challenge takes the following commands:
 * `bands`: This will print directories present within the directory `./data`.
 * `songs`: This takes a directory name (`bands`) and prints files present in the directory. The function `sanitize_path` in the challenge looks for the directory traversal character `../` but you can bypass the check and do the directory traversal to the one-level-up directory by using the string `..` as a directory name. 
 ```c
 static bool sanitize_path(char *buffer) {
  if (strstr(buffer, "../") != NULL) {
    return false;
  }

  return true;
}
 ```
 * `open`: This opens files and stores the file descriptors in a global variable (`records`). Using `RLIMIT_NOFILE`, the application allows a maximum of 32 files to be opened at a time. The directory traversal can't be used to open the `flag` file because `open` checks if the filename contains the string "file" at `(2)`.
 ```c
 // Better safe then sorry. Make sure that the path also doesn't point to a
  // symbolic link.
  int fd2 = open(path, O_RDONLY | O_NOFOLLOW);  //<------ (1)
  if (fd2 == -1) {
    printf("[-] Detected attempt to open a symbolic link!\n");

    // Some kind of attack detected?
    return true;
  }
  close(fd2);

  // Extra check to protect the flag.
  if (strstr(path, "flag") != NULL) { // <----- (2)
    printf("[-] Not today\n");

    close(globals::records.back());
    globals::records.pop_back();
    return false;
  }

 ```
 
This check can be bypassed by using the limit of 32 on the file descriptor. To exploit, open 32 files (note that the last file must be the `flag` file). At `(1)`, you can see that the function opens the 33rd file descriptor to check if the file is a symbolic link or not. The function `open` will return  `-1` because the maximum allowed FD is reached. The following `if` condition turns `True` and the checks for the file `flag` is bypassed. 
 
 * `read`: This takes the index (`Record ID`) for the global array `records` from the user and reads the file stored at that index. This is used to read a file opened via the `open` commands.  At `(6)`, this command checks for the string `DrgnS` in file content before printing it to the output. The flag contains the string `DrgnS` and so the check will prevent the reading of the flag.
 
 ```
  char buffer[4096];       //<----------------------------------- (3)
  ssize_t bytes_read = read_line_buffered(globals::records[idx],
                                          buffer, sizeof(buffer)); //<--------------- (4)
                                          
  // Let's make sure we're not disclosing any sensitive data due to potential
  // bugs in the program.
  if (bytes_read > 0) {                  //<----------------------------------- (5)
    if (strstr(buffer, "DrgnS")) {       //<----------------------------------- (6)
      printf("[-] Attack detected and stopped!\n");

      assert(close(globals::records[idx]) == 0);  //<-----------------------------------  (7)
      memmove(&globals::records[idx], &globals::records[idx + 1],
              (globals::records.size() - idx - 1) * sizeof(int));
      globals::records.pop_back();
      return true;
    }
  }
 ```

other commands such as `write`,`close`, and `exit` are available but they are not valuable from the exploit point of view. 


### Exploit:

The premise of the exploit is that assertions in the source code are not compiled out in the binary. The assertion at `(7)` closing the file descriptor will not occur. It means when the string `DrgnS` is found in the file content, a file descriptor is removed from the global array `records` without closing the file. 

The command `open` allows the maximum 16 FDs to be stored in the global array `records`. However, we can have more than 16 FDs open at a time by reading a file that contains the string "DrgnS". The binary `lyrics` contains the string and it will be used to open more than 16 FDs.
```c
  // Don't allow opening too many lyrics at once.
  if (globals::records.size() >= 16) {  // <------ (8)
    return false;
  }
```
To exploit you will follow the following steps:
* Open the `lyrics` file 16 times using the directory traversal. This will open total 16 FDs (file descriptors). 
* The default `stdin`, `stdout`, and `stderr` FDs are available so the total opened FDs are 19.
* Calls the read command 13 times to clear 13 FD elements of the global array `records` without closing them.
* Open 12 more lyrics files to reach a total of 31 (19 +12) FDs. In my exploit, I used the lyrics file `./data/Metallica/Battery`.
* Open the flag file as 32nd FD. 
* Read `./data/Metallica/Battery` till the end of the file. 
* Read the flag file. This will not print out the flag because of the check at (6).
* Read the `./data/Metallica/Battery` file again which reached the EOF. This should print out the flag because the variable `buffer` is not initialized at `(3)` and it may contain a stale value (in this case the flag). We already reached the EOF so `bytes_read` at `(4)`  is 0 and the `if` condition at `(5)` fails. This means the check of the string "DrgnS" is bypassed and the flag will be displayed.  



#### Other write-ups:
* https://changochen.github.io/2018-09-29-Teaser-Dragon-CTF-2018.html
* https://expend20.github.io/2018/09/30/dragon-teaser-production.html
