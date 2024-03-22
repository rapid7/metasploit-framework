##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::Tcp
  include Auxiliary::Scanner
  include Auxiliary::Report
  include Exploit::Remote::X11

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
    sock.put(X11CONNECTIONREQUEST.new.to_binary_s) # x11 session establish
    packet = sock.get_once(-1, 1)
    begin
      connection = X11CONNECTION.read(packet)
    rescue EOFError
      vprint_bad("Connection packet malformed (size: #{packet.length}), attempting to get read more data")
      packet += sock.get_once(-1, 1)
      begin
        connection = X11CONNECTION.read(packet)
        if connection.success == 1
          print_good("#{ip} - Successly established X11 connection")
          vprint_status("  Vendor: #{connection.vendor}")
          vprint_status("  Version: #{connection.protocol_version_major}.#{connection.protocol_version_minor}")
          vprint_status("  Screen Resolution: #{connection.screen_width_in_pixels}x#{connection.screen_height_in_pixels}")
          vprint_status("  Resource ID: #{connection.resource_id_base.inspect}")
          vprint_status("  Screen root: #{connection.screen_root.inspect}")
          report_note(
            host: ip,
            proto: 'tcp',
            sname: 'x11',
            port: rport,
            type: 'x11.server_vendor',
            data: "Open X Server (#{connection.vendor})"
          )
        else
          vprint_error("#{ip} Access Denied")
        end
      rescue StandardError
        vprint_bad('Failed to parse X11 connection initialization response packet')
      end
    end

    disconnect
  rescue ::Rex::ConnectionError
  rescue ::Errno::EPIPE
  end
end
