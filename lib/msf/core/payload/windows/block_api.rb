# -*- coding: binary -*-


module Msf

###
#
# Basic block_api stubs for Windows ARCH_X86 payloads
#
###
module Payload::Windows::BlockApi

  def initialize(info = {})
    ret = super( info )
    register_advanced_options(
      [
        Msf::OptBool.new('PrependStackContext', [ false, "Pre-populate stack with block-API resolver requirements" ])
      ], Msf::Payload::Windows::BlockApi)
    ret
  end

  def asm_block_api(opts={})
    prep = datastore['PrependStackContext'] ? asm_prep_raw_stack : ''
    prep + Rex::Payloads::Shuffle.from_graphml_file(
      File.join(Msf::Config.install_root, 'data', 'shellcode', 'block_api.x86.graphml'),
      arch: ARCH_X86,
      name: 'api_call'
    )
  end

  def asm_prep_raw_stack(opts={})
    asm = %Q^
      pusha
      call stack_prepped
      popa
      xor eax,eax
      ret
    stack_prepped:
    ^
  end

end
end
