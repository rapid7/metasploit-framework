#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# 
# here we will build an executable file that will shut down the machine
# when run
# TODO #include <windows.h>, use some struct handling
#

require 'metasm'

include Metasm

pe = PE.assemble Ia32.new, <<EOS
.section '.text' r w x

.import kernel32 GetCurrentProcess getcurrentprocess
.import advapi32 OpenProcessToken  openprocesstoken
.import advapi32 LookupPrivilegeValueA lookupprivilegevalue
.import advapi32 AdjustTokenPrivileges adjusttokenprivileges
.import user32   ExitWindowsEx exitwindowsex

.entrypoint

; OpenProcessToken(GetCurrentProcess, ADJUST_PRIV | QUERY, &htok)
push htok
push 28h
call getcurrentprocess
push eax
call openprocesstoken

; LookupPrivVal(0, SE_SHUTDOWN, &tokpriv.priv[0].luid)
push tokpriv_luid
push privname
push 0
call lookupprivilegevalue

; tokpriv.privcnt = 1 ; tokpriv.priv[0].attr = ENABLED
mov dword ptr [tokpriv], 1
mov dword ptr [tokpriv_attr], 2

; AdjustTokenPrivileges(htok, 0, &tokpriv, 0, 0, 0)
xor eax, eax
push eax
push eax
push eax
push tokpriv
push eax
push dword ptr [htok]
call adjusttokenprivileges

; ExitWindowsEx(SHUTDOWN | FORCE, OS | MINORUPDATE | PLANNED)
push 80020003h
push 5
call exitwindowsex

ret

.align 4
htok dd ?
tokpriv:
 tokpriv_count dd ?
 tokpriv_luid  dd ?, ?
 tokpriv_attr  dd ?
privname db "SeShutdownPrivilege\0"

EOS
pe.encode_file 'metasm-shutup.exe'
