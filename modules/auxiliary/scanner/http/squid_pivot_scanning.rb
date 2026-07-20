##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/socket/range_walker'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Squid Proxy Port Scanner',
      'Description' => %q{
        A exposed Squid proxy will usually allow an attacker to make requests on
        their behalf. If misconfigured, this may give the attacker information
        about devices that they cannot normally reach. For example, an attacker
        may be able to make requests for internal IP addresses against an open
        Squid proxy exposed to the Internet, therefore performing a port scan
        against the internal network.

        The `auxiliary/scanner/http/open_proxy` module can be used to test for
        open proxies, though a Squid proxy does not have to be on the open
        Internet in order to allow for pivoting (e.g. an Intranet Squid proxy
        which allows the attack to pivot to another part of the internal
        network).

        This module will not be able to scan network ranges or ports denied by
        Squid ACLs. Fortunately it is possible to detect whether a host was up
        and the port was closed, or if the request was blocked by an ACL, based
        on the response Squid gives. This feedback is provided to the user in
        meterpreter `VERBOSE` output, otherwise only open and permitted ports
        are printed.
        },
      'Author' => [
        'willis', # Original meterpreter module
        '0x44434241' # Detection updates and documentation
      ],
      'References' => [
        'URL', 'http://wiki.squid-cache.org/SquidFaq/SecurityPitfalls'
      ],
      'License'	=> MSF_LICENSE
    )

    register_options(
      [
        OptString.new('RANGE', [true, 'IPs to scan through Squid proxy', '']),
        OptString.new('PORTS', [true, 'Ports to scan; must be TCP', '21,80,139,443,445,1433,1521,1723,3389,8080,9100']),
        OptBool.new('MANUAL_CHECK', [true, 'Stop the scan if server seems to answer positively to every request', true]),
        OptString.new('CANARY_IP', [true, 'The IP to check if the proxy always answers positively; the IP should not respond.', '1.2.3.4'])
      ]
    )
  end

  def run_host(target_host)
    begin
      iplist = Rex::Socket::RangeWalker.new(datastore['RANGE'])
      portlist = Rex::Socket.portspec_crack(datastore['PORTS'])
      dead = false

      if portlist.empty?
        raise Msf::OptionValidateError.new(['PORTS'])
      end

      vprint_status("[#{rhost}] Verifying manual testing is not required...")

      manual = false
      # request a non-existent page first to make sure the server doesn't respond with a 200 to everything.
      res_test = send_request_cgi({
        'uri' => "http://#{datastore['CANARY_IP']}:80",
        'method' => 'GET',
        'data' => '',
        'version' => '1.0',
        'vhost' => ''
      }, 10)

      if res_test && res_test.body && (res_test.code == 200)
        print_error("#{rhost} likely answers positively to every request, check it manually.")
        print_error("\t\t Proceeding with the scan may increase false positives.")
        manual = true
      end

      iplist.each do |target|
        next if manual && datastore['MANUAL_CHECK']

        alive = nil

        portlist.each do |port|
          next if dead

          vprint_status("[#{rhost}] Requesting #{target}:#{port}")
          if port == 443
            res = send_request_cgi({
              'uri' => "https://#{target}:#{port}",
              'method' => 'GET',
              'data' => '',
              'version' => '1.0',
              'vhost' => ''
            }, 10)
          else
            res = send_request_cgi({
              'uri' => "http://#{target}:#{port}",
              'method' => 'GET',
              'data' => '',
              'version' => '1.0',
              'vhost' => ''
            }, 10)
          end

          if res && res.body
            # Look at the HTTP headers back from Squid first, for some easy error detection.
            if res.headers.key?('X-Squid-Error')
              case res.headers['X-Squid-Error']
              when /ERR_CONNECT_FAIL/
                # Usually a HTTP 503, page body can give some more information. Example:
                # <p id="sysmsg">The system returned: <i>(111) Connection refused</i></p>
                if res.body =~ /id="sysmsg".*Connection refused/
                  if alive.nil?
                    print_good("[#{rhost}] #{target} is alive.")
                    alive = true
                  end
                  vprint_status("[#{rhost}] #{target} is alive but #{port} is closed.")
                elsif res.body =~ /id="sysmsg".*No route to host/
                  dead = true
                  print_error("[#{rhost}] No route to #{target}")
                end
              when /ERR_ACCESS_DENIED/
                # Indicates that the Squid ACLs do not allow connecting to this port.
                # See: https://wiki.squid-cache.org/SquidFaq/SquidAcl
                vprint_status("[#{rhost}] #{target}:#{port} likely blocked by ACL.")
              when /ERR_DNS_FAIL/
                # Squid could not resolve the destination hostname.
                dead = true
                print_error("[#{rhost}] Squid could not resolve '#{target}', try putting the IP in the RANGE parameter if known.")
              else
                print_error("[#{rhost}] #{target}:#{port} unknown Squid proxy error: '#{res.headers['X-Squid-Error']}' (HTTP #{res.code})")
              end
              next # Skip to next port if the host is not marked as dead
            end

            # By this stage, we've likely got a good connection. Parsing the body might no longer be reasonable if the
            # destination port is not serving HTTP (eg: SSH), but we can derive information from the headers Squid
            # returns.
            if res.code.between?(300, 399)
              # We can be more verbose if we have a known redirect.
              print_good("[#{rhost}] #{target}:#{port} seems open (HTTP #{res.code} redirect to: '#{res.headers['Location']}', server header: '#{res.headers['Server']}')")
              report_service(host: target, port: port, name: res.headers['Server'], info: 'Redirect to: ' + res.headers['Location'])
            else
              # 200 OK, 404 Not Found etc - still indicates the port was open and responding.
              server = res.headers['Server'] || 'unknown'
              print_good("[#{rhost}] #{target}:#{port} seems open (HTTP #{res.code}, server header: '#{server}').")
              report_service(host: target, port: port, name: server, info: res.body)
            end

          end
        end
        dead = false
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
