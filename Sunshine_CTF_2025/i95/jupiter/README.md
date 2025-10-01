```
 Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'$ORIGIN'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

A `dprintf` formatted string vulnerability allowed you to overwrite the higher bytes of the local variable `secret_key` to write "0x1337" using the `%n` operator.

`sun{F0rmat_str!ngs_4re_sup3r_pOwerFul_r1gh7??}`
