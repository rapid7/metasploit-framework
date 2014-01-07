# -*- coding: binary -*-

module Msf
class Post
module Windows

module LDAP

  include Msf::Post::Windows::Error
  include Msf::Post::Windows::ExtAPI

  LDAP_SIZELIMIT_EXCEEDED = 0x04
  LDAP_OPT_SIZELIMIT = 0x03
  LDAP_AUTH_NEGOTIATE = 0x0486

  DEFAULT_PAGE_SIZE = 500

  def query(filter, max_results, fields)
    default_naming_context = get_default_naming_context
    vprint_status("Default Naming Context #{default_naming_context}")
    if load_extapi
      domain_name = default_naming_context.gsub("DC=","").gsub(",",".")
      vprint_status(domain_name)
      return session.extapi.adsi.domain_query(domain_name, filter, max_results, DEFAULT_PAGE_SIZE, fields)
    else
      bind_default_ldap_server(max_results) do |session_handle|
        return query_ldap(session_handle, default_naming_context, 2, filter, fields)
      end
    end
  end

  def get_default_naming_context
    bind_default_ldap_server(1) do |session_handle|
      print_status("Querying default naming context")

      query_result = query_ldap(session_handle, "", 0, "(objectClass=computer)", ["defaultNamingContext"])
      first_entry_fields = query_result[:results].first
      # Value from First Attribute of First Entry
      default_naming_context = first_entry_fields.first
      return default_naming_context
    end
  end

  # Performs a query on the LDAP session
  #
  # @param [Handle] LDAP Session Handle
  # @param [Integer] Pointer to string that contains distinguished name of entry to start the search
  # @param [Integer] Search Scope
  # @param [String] Search Filter
  # @param [Array] Attributes to retrieve
  # @return [Hash] Entries found
  def query_ldap(session_handle, base, scope, filter, fields)
    vprint_status ("Searching LDAP directory")
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

    if(search_count == 0)
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
        value_results = ""

        values = get_values_from_ber(ber, field)

        values_result = ""
        values_result = values.join(',') unless values.nil?
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
  # @param [Integer] Pointer to the Entry
  # @return [Array] Entry data structure
  def get_entry(pEntry)
    return client.railgun.memread(pEntry,41).unpack('LLLLLLLLLSCCC')
  end

  # Get BER Element data structure from LDAPMessage
  #
  # @param [String] The LDAP Message from the server
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
  # @param [String] BER data structure
  # @param [String] Attribute name
  # @return [Array] Returns array of values for the field
  def get_values_from_ber(ber_data, field)
    field_offset = ber_data.index(field)

    if field_offset.nil?
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
  # @param [int] the maximum number of results to return in a query
  # @return [LDAP Session Handle]
  def bind_default_ldap_server(size_limit)
    vprint_status ("Initializing LDAP connection.")
    init_result = wldap32.ldap_sslinitA("\x00\x00\x00\x00", 389, 0)
    session_handle = init_result['return']

    if session_handle == 0
      raise RuntimeError.new("Unable to initialize ldap server: #{init_result["ErrorMessage"]}")
    end

    vprint_status("LDAP Handle: #{session_handle}")

    vprint_status ("Setting Sizelimit Option")
    sl_result = wldap32.ldap_set_option(session_handle, LDAP_OPT_SIZELIMIT, size_limit)

    vprint_status ("Binding to LDAP server")
    bind_result = wldap32.ldap_bind_sA(session_handle, nil, nil, LDAP_AUTH_NEGOTIATE)

    bind = bind_result['return']

    unless bind == Error::SUCCESS
      vprint_status("Unbinding from LDAP service")
      wldap32.ldap_unbind(session_handle)
      raise RuntimeError.new("Unable to bind to ldap server: #{bind}")
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
