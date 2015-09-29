.code

MyGetTextMetricsW PROC
		mov r10, rcx
		mov eax, 4214
		syscall
		ret
MyGetTextMetricsW ENDP

END