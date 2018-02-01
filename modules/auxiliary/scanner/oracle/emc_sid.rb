##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Oracle Enterprise Manager Control SID Discovery',
      'Description' => %q{
          This module makes a request to the Oracle Enterprise Manager Control Console
        in an attempt to discover the SID.
      },
      'References'  =>
        [
          [ 'URL', 'http://dsecrg.com/files/pub/pdf/Different_ways_to_guess_Oracle_database_SID_(eng).pdf' ],
        ],
      'Author'      => [ 'MC' ],
      'License'     => MSF_LICENSE
    )

    register_options([Opt::RPORT(1158),])
  end

  def run_host(ip)
    begin
      res = send_request_raw({
        'uri'     => '/em/console/logon/logon',
        'method'  => 'GET',
      }, 5)

      return if not res
        if (res.code == 200)
        sid = res.body.scan(/Login to Database:(\w+)/)
          report_note(
              :host	=> ip,
              :port	=> datastore['RPORT'],
              :proto	=> 'tcp',
              :type	=> 'oracle_sid',
              :data	=> sid,
              :update => :unique_data
          )
          print_status("Discovered SID: '#{sid}' for host #{ip}")
        else
          print_error("Unable to retrieve SID for #{ip}...")
        end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
