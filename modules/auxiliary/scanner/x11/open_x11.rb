##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::Tcp
  include Auxiliary::Scanner
  include Auxiliary::Report
  include Msf::Exploit::Remote::X11::Connect

  def initialize
    super(
      'Name'	=> 'X11 No-Auth Scanner',
      'Description'	=> %q{
        This module scans for X11 servers that allow anyone
        to connect without authentication.
      },
      'Author'	=> [
        'tebo <tebodell[at]gmail.com>', # original module
        'h00die' # X11 library
      ],
      'References' => [
        ['OSVDB', '309'],
        ['CVE', '1999-0526'],
      ],
      'License'	=> MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => [],
        'RelatedModules' => [
          'auxiliary/gather/x11_keyboard_spy',
        ]
      }
    )

    register_options([
      Opt::RPORT(6000)
    ])
  end

  def run_host(ip)
    connect
    connection = x11_connect

    if connection.nil?
      vprint_bad('No connection, or bad X11 response received')
      return
    end

    if connection.header.success == 1
      x11_print_connection_info(connection, ip, rport)
      report_service(
        host: rhost,
        proto: 'tcp',
        port: rport,
        info: "Open X Server (#{connection.body.vendor}) #{connection.body.screen_width_in_pixels}x#{connection.body.screen_height_in_pixels}",
        name: 'X11'
      )
    else
      vprint_error("#{ip} Access not successful: #{connection.body.reason}")
    end

    disconnect
  rescue ::Errno::EPIPE, ::Rex::ConnectionError
    vprint_bad('No connection, or bad X11 response received')
    return
  end
end
