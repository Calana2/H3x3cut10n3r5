```
 Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'$ORIGIN'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

The program read 0x64 bytes in a smaller buffer so we had a buffer overflow.

The program had a `win(arg1, arg2)` function that checks that `arg1=0x31337` and `arg2='/bin/sh'`. We could not set `rdi` and `rsi` but these are copied befor the checks into `rbp-0x4` and `rbp-0x10` respectively so we could jump a little furter and prepare a stack frame thatmet the conditions.

`sun{D!d_y0u_s3e_thE_IM4P_spAce_laUncH??}`
