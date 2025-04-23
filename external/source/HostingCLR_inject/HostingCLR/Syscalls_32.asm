.model flat, c

.code


; Reference: https://j00ru.vexillium.org/syscalls/nt/32/

; Windows 7 SP1 / Server 2008 R2 specific syscalls

ZwProtectVirtualMemory7SP1 proc
    mov     eax, 0D6h
    mov     edx, esp
    int     2Eh
    ret     20
ZwProtectVirtualMemory7SP1 endp

ZwWriteVirtualMemory7SP1 proc
    mov     eax, 18Fh
    mov     edx, esp
    int     2Eh
    ret     20
ZwWriteVirtualMemory7SP1 endp

ZwReadVirtualMemory7SP1 proc
    mov     eax, 115h
    mov     edx, esp
    int     2Eh
    ret     20
ZwReadVirtualMemory7SP1 endp

; Windows 8 / Server 2012 specific syscalls

ZwProtectVirtualMemory80 proc
    mov     eax, 0C3h
    mov     edx, esp
    int     2Eh
    ret     20
ZwProtectVirtualMemory80 endp

ZwWriteVirtualMemory80 proc
    mov     eax, 2h
    mov     edx, esp
    int     2Eh
    ret     20
ZwWriteVirtualMemory80 endp

ZwReadVirtualMemory80 proc
    mov     eax, 83h
    mov     edx, esp
    int     2Eh
    ret     20
ZwReadVirtualMemory80 endp

; Windows 8.1 / Server 2012 R2 specific syscalls

ZwProtectVirtualMemory81 proc
    mov     eax, 0C6h
    mov     edx, esp
    int     2Eh
    ret     20
ZwProtectVirtualMemory81 endp

ZwWriteVirtualMemory81 proc
    mov     eax, 3h
    mov     edx, esp
    int     2Eh
    ret     20
ZwWriteVirtualMemory81 endp

ZwReadVirtualMemory81 proc
    mov     eax, 86h
    mov     edx, esp
    int     2Eh
    ret     20
ZwReadVirtualMemory81 endp

; Windows 10 / Server 2016 specific syscalls

ZwWriteVirtualMemory10 proc
    mov     eax, 4h
    mov     edx, esp
    int     2Eh
    ret     20
ZwWriteVirtualMemory10 endp

; Annoying - different for each version of Win10
; 1507, 1511

ZwProtectVirtualMemory10_1 proc
    mov     eax, 0C8h
    mov     edx, esp
    int     2Eh
    ret     20
ZwProtectVirtualMemory10_1 endp

ZwReadVirtualMemory10_1 proc
    mov     eax, 88h
    mov     edx, esp
    int     2Eh
    ret     20
ZwReadVirtualMemory10_1 endp

; 1607

ZwProtectVirtualMemory10_2 proc
    mov     eax, 0CAh
    mov     edx, esp
    int     2Eh
    ret     20
ZwProtectVirtualMemory10_2 endp

ZwReadVirtualMemory10_2 proc
    mov     eax, 89h
    mov     edx, esp
    int     2Eh
    ret     20
ZwReadVirtualMemory10_2 endp

; 1703

ZwProtectVirtualMemory10_3 proc
    mov     eax, 0CCh
    mov     edx, esp
    int     2Eh
    ret     20
ZwProtectVirtualMemory10_3 endp

ZwReadVirtualMemory10_3 proc
    mov     eax, 89h
    mov     edx, esp
    int     2Eh
    ret     20
ZwReadVirtualMemory10_3 endp

; 1709..22H2 - thankfully some consistency

ZwProtectVirtualMemory10_4 proc
    mov     eax, 0CEh
    mov     edx, esp
    int     2Eh
    ret     20
ZwProtectVirtualMemory10_4 endp

ZwReadVirtualMemory10_4 proc
    mov     eax, 8Ah
    mov     edx, esp
    int     2Eh
    ret     20
ZwReadVirtualMemory10_4 endp


end