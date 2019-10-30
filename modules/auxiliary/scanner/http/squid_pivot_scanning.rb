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
      'Name'          => 'Squid Proxy Port Scanner',
      'Description'   => %q{
        A misconfigured Squid proxy can allow an attacker to make requests on his behalf.
          This may give the attacker information about devices that he cannot reach but the
          Squid proxy can. For example, an attacker can make requests for internal IP addresses
          against a misconfigured open Squid proxy exposed to the Internet, therefore performing
          an internal port scan. The error messages returned by the proxy are used to determine
          if the port is open or not.

          Many Squid proxies use custom error codes so your mileage may vary. The open_proxy
          module can be used to test for open proxies, though a Squid proxy does not have to be
          open in order to allow for pivoting (e.g. an Intranet Squid proxy which allows
          the attack to pivot to another part of the network).
      },
      'Author'	       => ['willis'],
      'References'	 =>
        [
              'URL','http://wiki.squid-cache.org/SquidFaq/SecurityPitfalls'
        ],

      'License'	=> MSF_LICENSE
    )

    register_options(
      [
        OptString.new('RANGE', [true, "IPs to scan through Squid proxy", '']),
        OptString.new('PORTS', [true, "Ports to scan; must be TCP", "21,80,139,443,445,1433,1521,1723,3389,8080,9100"]),
        OptBool.new('MANUAL_CHECK',[true,"Stop the scan if server seems to answer positively to every request",true]),
        OptString.new('CANARY_IP',[true,"The IP to check if the proxy always answers positively; the IP should not respond.","1.2.3.4"])
      ])

  end

  def run_host(target_host)

    begin
        iplist = Rex::Socket::RangeWalker.new(datastore['RANGE'])
        dead = false
        portlist = Rex::Socket.portspec_crack(datastore['PORTS'])

        if portlist.empty?
          raise Msf::OptionValidateError.new(['PORTS'])
        end

        vprint_status("[#{rhost}] Verifying manual testing is not required...")

        manual = false
        # request a non-existent page first to make sure the server doesn't respond with a 200 to everything.
        res_test = send_request_cgi({
          'uri'          => "http://#{datastore['CANARY_IP']}:80",
          'method'       => 'GET',
          'data'  =>      '',
          'version' => '1.0',
          'vhost' => ''
        }, 10)

        if res_test and res_test.body and (res_test.code == 200)
          print_error("#{rhost} likely answers positively to every request, check it manually.")
          print_error("\t\t Proceeding with the scan may increase false positives.")
          manual = true
        end


        iplist.each do |target|
          next if manual and datastore['MANUAL_CHECK']

          portlist.each do |port|
            next if dead

            vprint_status("[#{rhost}] Requesting #{target}:#{port}")
            if port==443
              res = send_request_cgi({
                'uri'          => "https://#{target}:#{port}",
                'method'       => 'GET',
                'data'  =>      '',
                'version' => '1.0',
                'vhost' => ''
                }, 10)
            else
              res = send_request_cgi({
                'uri'          => "http://#{target}:#{port}",
                'method'       => 'GET',
                'data'  =>      '',
                'version' => '1.0',
                'vhost' => ''
              }, 10)
            end

            if res and res.body

              if res.code == 200 or res.body =~ /Zero/ or res.code == 404 or res.code == 401
                print_good("[#{rhost}] #{target}:#{port} seems OPEN")
                report_service(:host => target, :port => port, :name => "unknown", :info => res.body )
              end
              if res.body =~ /No route to host/
                dead = true
                print_error("[#{rhost}] #{target} is DEAD")
              end

              print_status("[#{rhost}] #{target}:#{port} blocked by ACL") if res.body =~ /Access control/

              if res.body =~ /Connection refused/ or res.body =~ /service not listening/
                report_host(:host => target)
                print_good("[#{rhost}] #{target} is alive but #{port} is CLOSED")
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
