# -*- coding: binary -*-


module Msf

###
#
# Basic block_api stubs for Windows ARCH_X64 payloads
#
###
module Payload::Windows::BlockApi_x64

  def initialize(info = {})
    ret = super( info )
    register_advanced_options(
      [
        Msf::OptBool.new('PrependStackContext', [ false, "Pre-populate stack with block-API resolver requirements" ])
    ], Msf::Payload::Windows::BlockApi_x64)
    ret
  end

  def asm_block_api(opts={})
    prep = datastore['PrependStackContext'] ? asm_prep_raw_stack : ''
    prep + Rex::Payloads::Shuffle.from_graphml_file(
      File.join(Msf::Config.install_root, 'data', 'shellcode', 'block_api.x64.graphml'),
      arch: ARCH_X64,
      name: 'api_call'
    )
  end

  def asm_prep_raw_stack(opts={})
    asm = %Q^
      push r12
      push r13
      push r14
      push r15
      push rbp
      call stack_prepped
      pop rbp
      pop r15
      pop r14
      pop r13
      pop r12
      xor rax,rax
      ret
    stack_prepped:
    ^
    asm
  end

end
end
