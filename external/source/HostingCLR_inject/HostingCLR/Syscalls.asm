.code

; Reference: https://j00ru.vexillium.org/syscalls/nt/64/

; Windows 7 SP1 / Server 2008 R2 specific syscalls

ZwProtectVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 4Dh
		syscall
		ret
ZwProtectVirtualMemory7SP1 endp

ZwWriteVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 37h
		syscall
		ret
ZwWriteVirtualMemory7SP1 endp

ZwReadVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 3Ch
		syscall
		ret
ZwReadVirtualMemory7SP1 endp

; Windows 8 / Server 2012 specific syscalls

ZwProtectVirtualMemory80 proc
		mov r10, rcx
		mov eax, 4Eh
		syscall
		ret
ZwProtectVirtualMemory80 endp

ZwWriteVirtualMemory80 proc
		mov r10, rcx
		mov eax, 38h
		syscall
		ret
ZwWriteVirtualMemory80 endp

ZwReadVirtualMemory80 proc
		mov r10, rcx
		mov eax, 3Dh
		syscall
		ret
ZwReadVirtualMemory80 endp

; Windows 8.1 / Server 2012 R2 specific syscalls

ZwProtectVirtualMemory81 proc
		mov r10, rcx
		mov eax, 4Fh
		syscall
		ret
ZwProtectVirtualMemory81 endp

ZwWriteVirtualMemory81 proc
		mov r10, rcx
		mov eax, 39h
		syscall
		ret
ZwWriteVirtualMemory81 endp

ZwReadVirtualMemory81 proc
		mov r10, rcx
		mov eax, 3Eh
		syscall
		ret
ZwReadVirtualMemory81 endp

; Windows 10 / Server 2016 specific syscalls
 
ZwProtectVirtualMemory10 proc
		mov r10, rcx
		mov eax, 50h
		syscall
		ret
ZwProtectVirtualMemory10 endp

ZwWriteVirtualMemory10 proc
		mov r10, rcx
		mov eax, 3Ah
		syscall
		ret
ZwWriteVirtualMemory10 endp

ZwReadVirtualMemory10 proc
		mov r10, rcx
		mov eax, 3Fh
		syscall
		ret
ZwReadVirtualMemory10 endp

end