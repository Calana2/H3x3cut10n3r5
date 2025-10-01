```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'$ORIGIN'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Stack overflow using `gets`. There is a check with a local integer and the value "0x1337C0DE" but it is after our buffer so we could overwrite it.

`sun{DeXtEr_was_!nnocent_Do4kEs_w4s_the_bAy_hRrb0ur_bu7cher_afterall!!}`
