##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MsSamr
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  include Msf::OptionalSession::SMB

  def initialize
    super(
      'Name' => 'SMB User Enumeration (SAM EnumUsers)',
      'Description' => 'Determine what users exist via the SAM RPC service',
      'Author' => 'hdm',
      'License' => MSF_LICENSE,
      'DefaultOptions' => {
        'DCERPC::fake_bind_multi' => false
      },
    )

    register_options(
      [
        OptBool.new('DB_ALL_USERS', [ false, "Add all enumerated usernames to the database", false ]),
      ]
    )
  end

  def rport
    @rport
  end

  def domain
    @smb_domain || super
  end

  def connect(*args, **kwargs)
    super(*args, **kwargs, direct: @smb_direct)
  end

  def run_host(_ip)
    if session
      run_session
      return
    end

    if datastore['RPORT'].blank? || datastore['RPORT'] == 0
      smb_services = [
        { port: 445, direct: true },
        { port: 139, direct: false }
      ]
    else
      smb_services = [
        { port: datastore['RPORT'], direct: datastore['SMBDirect'] }
      ]
    end

    smb_services.each do |smb_service|
      run_service(smb_service[:port], smb_service[:direct])
    end
  end

  def run_session
    simple = session.simple_client
    @rhost = simple.peerhost
    @rport = simple.peerport
    ipc_connect_result = simple.connect("\\\\#{simple.address}\\IPC$")
    unless ipc_connect_result
      print_error "Failed to connect to IPC in session #{session.sid}"
      return
    end
    tree = simple.client.tree_connects.last

    run_service_domain(tree)
    run_service_domain(tree, smb_domain: 'Builtin')
  rescue ::Timeout::Error
  rescue ::Exception => e
    print_error("Error: #{e.class} #{e}")
  end

  def run_service(port, direct)
    @rport = port
    @smb_direct = direct

    tree = connect_ipc

    run_service_domain(tree)
    run_service_domain(tree, smb_domain: 'Builtin')
  rescue ::Timeout::Error
  rescue ::Interrupt
    raise $!
  rescue ::Rex::ConnectionError
  rescue ::Rex::Proto::SMB::Exceptions::LoginError
    return
  rescue ::Exception => e
    print_error("Error: #{e.class} #{e}")
  ensure
    tree.disconnect! if tree
    disconnect
  end

  # Fingerprint a single host
  def run_service_domain(tree, smb_domain: nil)
    @smb_domain = smb_domain

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

    print_good("#{samr_con.domain_name} [ #{users.values.map { |name| name.encode('UTF-8') }.join(', ')} ] ( LockoutTries=#{lockout_info.lockout_threshold} PasswordMin=#{password_info.min_password_length} )")
    if datastore['DB_ALL_USERS']
      users.values.each do |username|
        report_username(samr_con.domain_name, username.encode('UTF-8'))
      end
    end
  ensure
    samr_con.samr.close_handle(samr_con.domain_handle) if samr_con.domain_handle
    samr_con.samr.close_handle(samr_con.server_handle) if samr_con.server_handle
  end

  def report_username(domain, username)
    service_data = {
      address: rhost,
      port: rport,
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
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
