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

It's a simple `gets` buffer overflow. There was a small validation with a `strcmp`and the string "Jaguars" but it could be bypassed because `gets` allows us to write null bytes. There was a `win()` function so we just ROPed there.

`sun{It4chI_b3ats_0b!to_nO_d!ff}`
