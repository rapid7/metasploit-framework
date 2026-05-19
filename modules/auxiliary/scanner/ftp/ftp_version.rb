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
      'Author' => 'hdm',
      'License' => MSF_LICENSE
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
