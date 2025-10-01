```
  Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./'
    SHSTK:      Enabled
    IBT:        Enabled
```

**`glibc version: 2.23`**

### Leaks

The program allowed you to alloc, write, read and free up to 16 chunks of arbitrary size. You could allocate two chunks — one larger than 0x400 bytes and a small sentinel— and then free them. After that, you can read the fd of the first chunk to obtain the address of libc's main_arena, and the fd of the second chunk to leak a heap address. 

Since the second chunk ends up in the tcachebin and safe-linking protection is in place, you need to perform a small calculation to get a valid heap address: `address = chunk->fd ^ (chunk_pos >> 12)`

However, because in the first element chunk->fd = 0, the operation reverses, resulting in: `leak = address << 12`

While you can use FSOP to get arbitrary execution, I wasn't familiar with the method. So what I did was use FSOP to get arbitrary reads and filter out `environ`, a libc symbol containing the stack address and the canary stack.

## RCE

With the stack leaks I was able to overwrite a saved RIP in the stack and put there my ROP chain. 




