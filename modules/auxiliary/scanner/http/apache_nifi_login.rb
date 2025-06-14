##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache NiFi Login Scanner',
        'Description' => %q{
          This module attempts to take login details for Apache NiFi websites
          and identify if they are valid or not.

          Tested against NiFi major releases 1.14.0 - 1.21.0, and 1.13.0
          Also works against NiFi <= 1.13.0, but the module needs to be adjusted:
          set SSL false
          set rport 8080
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(8443),
        OptString.new('TARGETURI', [ true, 'The URI of the Apache NiFi Application', '/'])
      ]
    )
    register_advanced_options([
      OptBool.new('SSL', [true, 'Negotiate SSL connection', true])
    ])
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      last_attempted_at: DateTime.now,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(ip)
    vprint_status("Checking #{ip}")
    res = send_request_cgi!(
      'uri' => normalize_uri(target_uri.path, 'nifi', 'login')
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 200

    fail_with(Failure::NotVulnerable, "Apache NiFi not detected on #{ip}") unless res.body =~ %r{js/nf/nf-namespace\.js\?([\d.]*)">}

    res = send_request_cgi!(
      'uri' => normalize_uri(target_uri.path, 'nifi-api', 'access', 'config')
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 200

    res_json = res.get_json_document

    unless res_json.dig('config', 'supportsLogin')
      print_error("#{peer} - User login not supported, try visiting /nifi to gain access")
      return
    end

    each_user_pass do |user, pass|
      res = send_request_cgi!(
        'uri' => normalize_uri(target_uri.path, 'nifi-api', 'access', 'token'),
        'method' => 'POST',
        'vars_post' => {
          'username' => user,
          'password' => pass
        }
      )
      fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
      if res.code == 201
        print_good("#{peer} - Apache NiFi - Login successful as '#{user}' with password '#{pass}'")
        report_cred(
          ip: rhost,
          port: rport,
          service_name: (ssl ? 'https' : 'http'),
          user: user,
          password: pass,
          proof: res.body.to_s
        )
      elsif res.code == 409
        fail_with(Failure::BadConfig, "#{peer} - Logins only accepted on HTTPS")
      else
        vprint_error("#{peer} - Apache NiFi - Failed to login as '#{user}' with password '#{pass}'")
      end
    end
  end
end
