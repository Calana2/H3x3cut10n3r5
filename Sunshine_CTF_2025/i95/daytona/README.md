```
  Arch:       aarch64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

The address of a local variable is leaked through `printf` as a `unsigned long long`. A `gets` based buffer overflow allows you to put shellcode on the stack and get rce.

`sun{ARM64_shEl1c0de_!s_pr3ttY_n3a7_dOnT_y0u_thInk?}`
