##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP Open Proxy Detection',
      'Description' => %q{
        Checks if an HTTP proxy is open. False positive are avoided
        verifying the HTTP return code and matching a pattern.
        The CONNECT method is verified only the return code.
        HTTP headers are shown regarding the use of proxy or load balancer.
      },
      'References'  =>
        [
          ['URL', 'http://en.wikipedia.org/wiki/Open_proxy'],
          ['URL', 'http://nmap.org/svn/scripts/http-open-proxy.nse'],
        ],
      'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptBool.new('MULTIPORTS', [ false, 'Multiple ports will be used: 80, 443, 1080, 3128, 8000, 8080, 8123', false ]),
        OptBool.new('VERIFYCONNECT', [ false, 'Enable CONNECT HTTP method check', false ]),
        OptString.new('CHECKURL', [ true, 'The web site to test via alleged web proxy', 'http://www.google.com' ]),
        OptString.new('VALIDCODES', [ true, "Valid HTTP code for a successfully request", '200,302' ]),
        OptString.new('VALIDPATTERN', [ true, "Valid pattern match (case-sensitive into the headers and HTML body) for a successfully request", '<TITLE>302 Moved</TITLE>' ]),
      ])

    register_wmap_options({
      'OrderID' => 1,
      'Require' => {},
    })
  end

  def run_host(target_host)

    check_url = datastore['CHECKURL']

    if datastore['VERIFYCONNECT']
      target_method = 'CONNECT'
      # CONNECT doesn't need <scheme> but need port
      check_url = check_url.gsub(/[http:\/\/|https:\/\/]/, '')
      if check_url !~ /:443$/
        check_url = check_url + ":443"
      end
    else
      target_method = 'GET'
      # GET only http request
      check_url = check_url.gsub(/https:\/\//, '')
      if check_url !~ /^http:\/\//i
        check_url = 'http://' + check_url
      end
    end

    target_ports = []

    if datastore['MULTIPORTS']
      target_ports = [ 80, 443, 1080, 3128, 8000, 8080, 8123 ]
    else
      target_ports.push(datastore['RPORT'].to_i)
    end

    target_proxy_headers = [ 'Forwarded', 'Front-End-Https', 'Max-Forwards', 'Via', 'X-Cache', 'X-Cache-Lookup', 'X-Client-IP', 'X-Forwarded-For', 'X-Forwarded-Host' ]

    target_ports.each do |target_port|
      verify_target(target_host,target_port,target_method,check_url,target_proxy_headers)
    end

  end

  def verify_target(target_host,target_port,target_method,check_url,target_proxy_headers)

    vprint_status("#{peer} - Sending a web request... [#{target_method}][#{check_url}]")

    datastore['RPORT'] = target_port

    begin
      res = send_request_cgi(
        'uri'     => check_url,
        'method'  => target_method,
        'version' => '1.1'
      )

      return if not res

      vprint_status("#{peer} - Returns with '#{res.code}' status code [#{target_method}][#{check_url}]")

      valid_codes = datastore['VALIDCODES'].split(/,/)

      target_proxy_headers_results = []
      target_proxy_headers.each do |proxy_header|
        if (res.headers.to_s.match(/#{proxy_header}: (.*)/))
          proxy_header_value = $1
          # Ok...I don't like it but works...
          target_proxy_headers_results.push("\n                          |_ #{proxy_header}: #{proxy_header_value}")
        end
      end

      if target_proxy_headers_results.any?
        proxy_headers = target_proxy_headers_results.join()
      end

      if datastore['VERIFYCONNECT']
        # Verifiying CONNECT we check only the return code
        if valid_codes.include?(res.code.to_s)

          print_good("#{peer} - Potentially open proxy [#{res.code}][#{target_method}]#{proxy_headers}")

          report_note(
            :host   => target_host,
            :port   => target_port,
            :method => target_method,
            :proto  => 'tcp',
            :sname  => (ssl ? 'https' : 'http'),
            :type   => 'OPEN HTTP PROXY',
            :data   => 'Open http proxy (CONNECT)'
          )

        end
      else
        # Verify return code && (headers.pattern or body.pattern)
        if valid_codes.include?(res.code.to_s) && (res.headers.include?(datastore['VALIDPATTERN']) || res.body.include?(datastore['VALIDPATTERN']))

          print_good("#{peer} - Potentially open proxy [#{res.code}][#{target_method}]#{proxy_headers}")

          report_note(
            :host   => target_host,
            :port   => target_port,
            :method => target_method,
            :proto  => 'tcp',
            :sname  => (ssl ? 'https' : 'http'),
            :type   => 'OPEN HTTP PROXY',
            :data   => 'Open http proxy (GET)'
          )

        end
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Timeout::Error, ::Errno::EPIPE => e
      vprint_error("#{peer} - The port '#{target_port}' is unreachable!")
      return nil
    end
  end
end
