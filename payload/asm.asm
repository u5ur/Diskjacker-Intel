.code
JmpToOriginal PROC
    add     rsp, 28h
    pop     rdi
    jmp     r8
JmpToOriginal ENDP
END