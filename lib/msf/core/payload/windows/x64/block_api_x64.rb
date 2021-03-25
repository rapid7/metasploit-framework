# -*- coding: binary -*-


module Msf

###
#
# Basic block_api stubs for Windows ARCH_X64 payloads
#
###
module Payload::Windows::BlockApi_x64

  def asm_block_api(opts={})
    Rex::Payloads::Shuffle.from_graphml_file(
      File.join(Msf::Config.install_root, 'data', 'shellcode', 'block_api.x64.graphml'),
      arch: ARCH_X64,
      name: 'api_call'
    )
  end

end
end
