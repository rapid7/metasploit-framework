##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::MsSamr

  # Scanner mixin should be near last
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  include Msf::OptionalSession::SMB

  def initialize
    super(
      'Name'        => 'SMB User Enumeration (SAM EnumUsers)',
      'Description' => 'Determine what local users exist via the SAM RPC service',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'DefaultOptions' => {
        'DCERPC::fake_bind_multi' => false
      },
    )

    register_options(
      [
        OptBool.new('DB_ALL_USERS', [ false, "Add all enumerated usernames to the database", false ]),
      ])
  end

  def rport
    @rport || super
  end

  def smb_direct
    @smbdirect || super
  end

  # Fingerprint a single host
  def run_host(ip)
    tree = connect_ipc

    samr_con = connect_samr(tree)

    lockout_info = samr_con.samr.samr_query_information_domain(
      domain_handle: samr_con.domain_handle,
      info_class: RubySMB::Dcerpc::Samr::DOMAIN_LOCKOUT_INFORMATION
    )

    password_info = samr_con.samr.samr_query_information_domain(
      domain_handle: samr_con.domain_handle,
      info_class: RubySMB::Dcerpc::Samr::DOMAIN_PASSWORD_INFORMATION
    )

    users = samr_con.samr.samr_enumerate_users_in_domain(
      domain_handle: samr_con.domain_handle,
      user_account_control: RubySMB::Dcerpc::Samr::USER_NORMAL_ACCOUNT
    )

    print_good("#{samr_con.domain_name} [ #{users.values.map { |name| name.encode('UTF-8') }.join(', ') } ] ( LockoutTries=#{lockout_info.lockout_threshold} PasswordMin=#{password_info.min_password_length} )")
  ensure
    samr_con.samr.close_handle(samr_con.domain_handle) if samr_con.domain_handle
    samr_con.samr.close_handle(samr_con.server_handle) if samr_con.server_handle
  end

  def store_username(username, domain, ip, rport, resp)
    service_data = {
      address: ip,
      port: rport,
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      proof: resp
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: username,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: domain,
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

end
