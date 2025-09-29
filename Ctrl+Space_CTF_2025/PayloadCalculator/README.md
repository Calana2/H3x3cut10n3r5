The script is NOT mine, I managed to gain remote code execution in local but failed remotely. Anyways is quite the same that I did.

```
 Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8045000)
    Stack:      Executable
    RWX:        Has RWX segments
    RUNPATH:    b'/app/lib32'
    Stripped:   No
```

**`glibc version: 2.23`**


### Leaks 
The program allowed you to allocate N chunks with sizes that add up to a maximum of 1000 bytes. You could leave it's content empty. The program wrote it's content in a file that you coul read. The cunks where already freed before your read so you could read a normal freed chunk to get a heap leak and a lot of bigs chunks and force coalescence and put them in the unsorted/large bin to get a libc leak.

### RCE
The program created a pointers chunk with calloc (the pointers to your N chunks). You could use some heap feng shui to:
- Allocate the first chunk of your N chunks over/before the chunk of pointers.
- Overwrite the second pointer to the address of `free@GOT`.
- Store the address of `system` in the second chunk.
- Store `"cat flag.txt;"` or whatever your command is in the third chunk.

Then when the third chunk gets freed it went from `free("/bin/sh")` to `system((/bin/sh)`.
