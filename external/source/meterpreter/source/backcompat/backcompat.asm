.model flat, C

.data
__imp__EncodePointer@4 dd dummy
__imp__DecodePointer@4 dd dummy
__imp__HeapSetInformation@16 dd dummy2

EXTERNDEF __imp__EncodePointer@4 : DWORD
EXTERNDEF __imp__DecodePointer@4 : DWORD
EXTERNDEF __imp__HeapSetInformation@16 : DWORD

.code

dummy proc
mov eax, [esp+4]
ret 4
dummy endp

dummy2 proc
mov eax, 1
ret 10h
dummy2 endp

end