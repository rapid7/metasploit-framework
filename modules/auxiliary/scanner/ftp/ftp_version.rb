##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'FTP Version Scanner',
        'Description' => %q{
          This module tries to identify the version of an FTP service by reading its banner.
        },
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
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue ::Rex::ConnectionError, ::IOError => e
    vprint_error(e.message)
  ensure
    disconnect
  end
end
