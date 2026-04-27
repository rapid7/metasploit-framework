##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'FTP Version Scanner',
      'Description' => 'Detect FTP Version.',
      'Author' => [
        'hdm',
        'g0tmi1k' # @g0tmi1k - additional features
      ],
      'License' => MSF_LICENSE,
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

    if (banner)
      banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
      print_good("FTP Banner: '#{banner_sanitized}'")
      report_service(host: rhost, port: rport, name: 'ftp', info: banner_sanitized)
    end

    disconnect
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue ::Rex::ConnectionError, ::IOError => e
    vprint_error(e.message)
  end
end
