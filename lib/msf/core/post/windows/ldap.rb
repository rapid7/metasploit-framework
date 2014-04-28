# -*- coding: binary -*-

module Msf
class Post
module Windows

#
# @see
#   http://msdn.microsoft.com/en-us/library/windows/desktop/aa366961(v=vs.85).aspx
#   MSDN: Lightweight Directory Access Protocol
module LDAP

  include Msf::Post::Windows::Error
  include Msf::Post::Windows::ExtAPI
  include Msf::Post::Windows::Accounts

  LDAP_SIZELIMIT_EXCEEDED = 0x04
  LDAP_OPT_SIZELIMIT = 0x03
  LDAP_AUTH_NEGOTIATE = 0x0486

  DEFAULT_PAGE_SIZE = 500

  ERROR_CODE_TO_CONSTANT =
  {
    0x0b => 'LDAP_ADMIN_LIMIT_EXCEEDED',
    0x47 => 'LDAP_AFFECTS_MULTIPLE_DSAS',
    0x24 => 'LDAP_ALIAS_DEREF_PROBLEM',
    0x21 => 'LDAP_ALIAS_PROBLEM',
    0x44 => 'LDAP_ALREADY_EXISTS',
    0x14 => 'LDAP_ATTRIBUTE_OR_VALUE_EXISTS',
    0x07 => 'LDAP_AUTH_METHOD_NOT_SUPPORTED',
    0x56 => 'LDAP_AUTH_UNKNOWN',
    0x33 => 'LDAP_BUSY',
    0x60 => 'LDAP_CLIENT_LOOP',
    0x05 => 'LDAP_COMPARE_FALSE',
    0x06 => 'LDAP_COMPARE_TRUE',
    0x0d => 'LDAP_CONFIDENTIALITY_REQUIRED',
    0x5b => 'LDAP_CONNECT_ERROR',
    0x13 => 'LDAP_CONSTRAINT_VIOLATION',
    0x5d => 'LDAP_CONTROL_NOT_FOUND',
    0x54 => 'LDAP_DECODING_ERROR',
    0x53 => 'LDAP_ENCODING_ERROR',
    0x57 => 'LDAP_FILTER_ERROR',
    0x30 => 'LDAP_INAPPROPRIATE_AUTH',
    0x12 => 'LDAP_INAPPROPRIATE_MATCHING',
    0x32 => 'LDAP_INSUFFICIENT_RIGHTS',
    0x31 => 'LDAP_INVALID_CREDENTIALS',
    0x22 => 'LDAP_INVALID_DN_SYNTAX',
    0x15 => 'LDAP_INVALID_SYNTAX',
    0x23 => 'LDAP_IS_LEAF',
    0x52 => 'LDAP_LOCAL_ERROR',
    0x36 => 'LDAP_LOOP_DETECT',
    0x5f => 'LDAP_MORE_RESULTS_TO_RETURN',
    0x40 => 'LDAP_NAMING_VIOLATION',
    0x5a => 'LDAP_NO_MEMORY',
    0x45 => 'LDAP_NO_OBJECT_CLASS_MODS',
    0x5e => 'LDAP_NO_RESULTS_RETURNED',
    0x10 => 'LDAP_NO_SUCH_ATTRIBUTE',
    0x20 => 'LDAP_NO_SUCH_OBJECT',
    0x42 => 'LDAP_NOT_ALLOWED_ON_NONLEAF',
    0x43 => 'LDAP_NOT_ALLOWED_ON_RDN',
    0x5c => 'LDAP_NOT_SUPPORTED',
    0x41 => 'LDAP_OBJECT_CLASS_VIOLATION',
    0x01 => 'LDAP_OPERATIONS_ERROR',
    0x50 => 'LDAP_OTHER',
    0x59 => 'LDAP_PARAM_ERROR',
    0x09 => 'LDAP_PARTIAL_RESULTS',
    0x02 => 'LDAP_PROTOCOL_ERROR',
    0x0a => 'LDAP_REFERRAL',
    0x61 => 'LDAP_REFERRAL_LIMIT_EXCEEDED',
    0x09 => 'LDAP_REFERRAL_V2',
    0x46 => 'LDAP_RESULTS_TOO_LARGE',
    0x51 => 'LDAP_SERVER_DOWN',
    0x04 => 'LDAP_SIZELIMIT_EXCEEDED',
    0x08 => 'LDAP_STRONG_AUTH_REQUIRED',
    0x00 => 'LDAP_SUCCESS',
    0x03 => 'LDAP_TIMELIMIT_EXCEEDED',
    0x55 => 'LDAP_TIMEOUT',
    0x34 => 'LDAP_UNAVAILABLE',
    0x0c => 'LDAP_UNAVAILABLE_CRIT_EXTENSION',
    0x11 => 'LDAP_UNDEFINED_TYPE',
    0x35 => 'LDAP_UNWILLING_TO_PERFORM',
    0x58 => 'LDAP_USER_CANCELLED',
    0x4c => 'LDAP_VIRTUAL_LIST_VIEW_ERROR'
  }

    def initialize(info = {})
      super
      register_options(
      [
        OptString.new('DOMAIN', [false, 'The domain to query or distinguished name (e.g. DC=test,DC=com)', nil]),
        OptInt.new('MAX_SEARCH', [true, 'Maximum values to retrieve, 0 for all.', 500]),
      ], self.class)
    end

  # Converts a Distinguished Name to DNS name
  #
  # @param dn [String] Distinguished Name
  # @return [String] DNS name
  def dn_to_domain(dn)
    if dn.include? "DC="
      return dn.gsub(',','').split('DC=')[1..-1].join('.')
    else
      return dn
    end
  end

  # Performs an ldap query
  #
  # @param filter [String] LDAP search filter
  # @param max_results [Fixnum] Maximum results
  # @param fields [Array<String>] Attributes to retrieve
  # @param domain [String] Optional domain or distinguished name
  # @return [Hash] Entries found
  # @raise [RuntimeError] Raised when the default naming context isn't
  #   specified as distinguished name.
  def query(filter, max_results, fields, domain=nil)
    domain ||= datastore['DOMAIN']
    domain ||= get_domain

    if domain.blank?
      raise RuntimeError, "Unable to find the domain to query."
    end

    if load_extapi
      return session.extapi.adsi.domain_query(domain, filter, max_results, DEFAULT_PAGE_SIZE, fields)
    else
      if domain and domain.include? "DC="
        default_naming_context = domain
        domain = dn_to_domain(domain)
      else
        default_naming_context = get_default_naming_context(domain)
      end

      bind_default_ldap_server(max_results, domain) do |session_handle|
        return query_ldap(session_handle, default_naming_context, 2, filter, fields)
      end
    end
  end

  # Performs a query to retrieve the default naming context
  #
  # @param domain [String] Optional domain or distinguished name
  # @return [String]
  def get_default_naming_context(domain=nil)
    bind_default_ldap_server(1, domain) do |session_handle|
      print_status("Querying default naming context")

      query_result = query_ldap(session_handle, "", 0, "(objectClass=computer)", ["defaultNamingContext"])
      first_entry_fields = query_result[:results].first
      # Value from First Attribute of First Entry
      default_naming_context = first_entry_fields.first
      vprint_status("Default naming context #{default_naming_context}")
      return default_naming_context
    end
  end

  # Performs a query on the LDAP session
  #
  # @param session_handle [Handle] LDAP Session Handle
  # @param base [Fixnum] Pointer to string that contains distinguished
  #   name of entry to start the search
  # @param scope [Fixnum] Search Scope
  # @param filter [String] Search Filter
  # @param fields [Array<String>] Attributes to retrieve
  # @return [Hash] Entries found
  def query_ldap(session_handle, base, scope, filter, fields)
    vprint_status("Searching LDAP directory")
    search = wldap32.ldap_search_sA(session_handle, base, scope, filter, nil, 0, 4)
    vprint_status("search: #{search}")

    if search['return'] == LDAP_SIZELIMIT_EXCEEDED
      print_error("LDAP_SIZELIMIT_EXCEEDED, parsing what we retrieved, try increasing the MAX_SEARCH value [0:LDAP_NO_LIMIT]")
    elsif search['return'] != Error::SUCCESS
      print_error("No results")
      wldap32.ldap_msgfree(search['res'])
      return
    end

    search_count = wldap32.ldap_count_entries(session_handle, search['res'])['return']

    if search_count == 0
      print_error("No entries retrieved")
      wldap32.ldap_msgfree(search['res'])
      return
    end

    print_status("Entries retrieved: #{search_count}")

    pEntries = []
    entry_results = []

    if datastore['MAX_SEARCH'] == 0
      max_search = search_count
    else
      max_search = [datastore['MAX_SEARCH'], search_count].min
    end

    0.upto(max_search - 1) do |i|

      if(i==0)
        pEntries[0] = wldap32.ldap_first_entry(session_handle, search['res'])['return']
      end

      if(pEntries[i] == 0)
        print_error("Failed to get entry")
        wldap32.ldap_msgfree(search['res'])
        return
      end

      vprint_status("Entry #{i}: 0x#{pEntries[i].to_s(16)}")

      entry = get_entry(pEntries[i])

      # Entries are a linked list...
      if client.platform =~ /x64/
        pEntries[i+1] = entry[4]
      else
        pEntries[i+1] = entry[3]
      end

      ber = get_ber(entry)

      field_results = []
      fields.each do |field|
        vprint_status("Field: #{field}")

        values = get_values_from_ber(ber, field)

        values_result = ""
        values_result = values.join(',') if values
        vprint_status("Values #{values}")

        field_results << values_result
      end

      entry_results << field_results
    end

    return {
        :fields  => fields,
        :results => entry_results
    }
  end

  # Gets the LDAP Entry
  #
  # @param pEntry [Fixnum] Pointer to the Entry
  # @return [Array] Entry data structure
  def get_entry(pEntry)
    return client.railgun.memread(pEntry,41).unpack('LLLLLLLLLSCCC')
  end

  # Get BER Element data structure from LDAPMessage
  #
  # @param msg [String] The LDAP Message from the server
  # @return [String] The BER data structure
  def get_ber(msg)
    ber = client.railgun.memread(msg[2],60).unpack('L*')

    # BER Pointer is different between x86 and x64
    if client.platform =~ /x64/
      ber_data = client.railgun.memread(ber[4], ber[0])
    else
      ber_data = client.railgun.memread(ber[3], ber[0])
    end

    return ber_data
  end

  # Search through the BER data structure for our Attribute.
  # This doesn't attempt to parse the BER structure correctly
  # instead it finds the first occurance of our field name
  # tries to check the length of that value.
  #
  # @param ber_data [String] BER data structure
  # @param field [String] Attribute name
  # @return [Array] Values for the given +field+
  def get_values_from_ber(ber_data, field)
    field_offset = ber_data.index(field)

    unless field_offset
      vprint_status("Field not found in BER: #{field}")
      return nil
    end

    # Value starts after our field string
    values_offset = field_offset + field.length
    values_start_offset = values_offset + 8
    values_len_offset = values_offset + 5
    curr_len_offset = values_offset + 7

    values_length =  ber_data[values_len_offset].unpack('C')[0]
    values_end_offset = values_start_offset + values_length

    curr_length = ber_data[curr_len_offset].unpack('C')[0]
    curr_start_offset = values_start_offset

    if (curr_length >= 127)
      curr_length = ber_data[curr_len_offset+1,4].unpack('N')[0]
      curr_start_offset += 4
    end

    curr_end_offset = curr_start_offset + curr_length

    values = []
    while (curr_end_offset < values_end_offset)
      values << ber_data[curr_start_offset..curr_end_offset]

      break unless ber_data[curr_end_offset] == "\x04"

      curr_len_offset = curr_end_offset + 1
      curr_length = ber_data[curr_len_offset].unpack('C')[0]
      curr_start_offset = curr_end_offset + 2
      curr_end_offset = curr_end_offset + curr_length + 2
    end

    # Strip trailing 0 or \x04 which is used to delimit values
    values.map! {|x| x[0..x.length-2]}

    return values
  end

  # Shortcut to the WLDAP32 Railgun Object
  # @return [Object] wldap32
  def wldap32
    client.railgun.wldap32
  end

  # Binds to the default LDAP Server
  # @param size_limit [Fixnum] Maximum number of results to return in a query
  # @param domain [String] Optional domain or distinguished name
  # @return LDAP session handle
  def bind_default_ldap_server(size_limit, domain=nil)
    vprint_status("Initializing LDAP connection.")

    # If domain is still null the API may be able to handle it...
    init_result = wldap32.ldap_sslinitA(domain, 389, 0)
    session_handle = init_result['return']
    if session_handle == 0
      raise RuntimeError.new("Unable to initialize ldap server: #{init_result["ErrorMessage"]}")
    end

    vprint_status("LDAP Handle: #{session_handle}")

    vprint_status("Setting Sizelimit Option")
    wldap32.ldap_set_option(session_handle, LDAP_OPT_SIZELIMIT, size_limit)

    vprint_status("Binding to LDAP server")
    bind_result = wldap32.ldap_bind_sA(session_handle, nil, nil, LDAP_AUTH_NEGOTIATE)

    bind = bind_result['return']
    unless bind == 0
      wldap32.ldap_unbind(session_handle)
      raise RuntimeError.new("Unable to bind to ldap server: #{ERROR_CODE_TO_CONSTANT[bind]}")
    end

    if (block_given?)
      begin
        yield session_handle
      ensure
        vprint_status("Unbinding from LDAP service")
        wldap32.ldap_unbind(session_handle)
      end
    else
      return session_handle
    end

    return session_handle
  end

end

end
end
end
