##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'FTP Version Scanner',
      'Description' => 'Detect FTP Version.',
      'Author' => [
        'hdm',
        'g0tmi1k' # @g0tmi1k - additional features
      ],
      'License' => MSF_LICENSE,
      'References' => [
        ['URL', 'https://www.ietf.org/rfc/rfc959']
      ],
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'Reliability' => [],
        'SideEffects' => [IOC_IN_LOGS]
      }
    )

    register_options(
      [
        Opt::RPORT(21),
      ]
    )

    # TODO: One day, might be nice to enum via doing: `send_cmd(['xxx'])` {STAT,SYST,FEAT}
    #       May need to be auth for these to work
    deregister_options('FTPUSER', 'FTPPASS')
  end

  def run_host(_target_host)
    connect(true, false)

    if banner
      print_good("FTP Banner: #{Rex::Text.to_hex_ascii(banner_version)}")
    else
      print_warning('No FTP banner received')
    end
  rescue ::Rex::ConnectionRefused
    vprint_error('Connection refused')
  rescue ::Rex::TimeoutError, ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNREFUSED => e
    vprint_error(e.message)
  rescue ::Interrupt
    raise $ERROR_INFO
  ensure
    disconnect
  end
end
