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
            # 0x09 => 'LDAP_REFERRAL_V2', alias for LDAP_PARTIAL_RESULTS
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
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    extapi_adsi_domain_query
                    stdapi_railgun_api
                    stdapi_railgun_memread
                  ]
                }
              }
            )
          )

          register_options(
            [
              OptString.new('DOMAIN', [false, 'The domain to query or distinguished name (e.g. DC=test,DC=com)', nil]),
              OptInt.new('MAX_SEARCH', [true, 'Maximum values to retrieve, 0 for all.', 500]),
            ], self.class
          )
        end

        # Converts a Distinguished Name to DNS name
        #
        # @param dn [String] Distinguished Name
        # @return [String] DNS name
        def dn_to_domain(dn)
          if dn.include? 'DC='
            return dn.gsub(',', '').split('DC=')[1..-1].join('.')
          else
            return dn
          end
        end

        # Performs an ldap query
        #
        # @param filter [String] LDAP search filter
        # @param max_results [Integer] Maximum results
        # @param fields [Array<String>] Attributes to retrieve
        # @param domain [String] Optional domain or distinguished name
        # @return [Hash] Entries found
        # @raise [RuntimeError] Raised when the default naming context isn't
        #   specified as distinguished name.
        def query(filter, max_results, fields, domain = nil)
          domain ||= datastore['DOMAIN']
          domain ||= get_domain

          if domain.blank?
            raise 'Unable to find the domain to query.'
          end

          if session.commands.include?(Rex::Post::Meterpreter::Extensions::Extapi::COMMAND_ID_EXTAPI_ADSI_DOMAIN_QUERY)
            return session.extapi.adsi.domain_query(domain, filter, max_results, DEFAULT_PAGE_SIZE, fields)
          else
            if domain and domain.include? 'DC='
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
        def get_default_naming_context(domain = nil)
          bind_default_ldap_server(1, domain) do |session_handle|
            print_status('Querying default naming context')

            query_result = query_ldap(session_handle, '', 0, '(objectClass=computer)', ['defaultNamingContext'])
            first_entry_fields = query_result[:results].first
            # Value from First Attribute of First Entry
            default_naming_context = first_entry_fields.first[:value]
            vprint_status("Default naming context #{default_naming_context}")
            return default_naming_context
          end
        end

        # Performs a query on the LDAP session
        #
        # @param session_handle [Handle] LDAP Session Handle
        # @param base [Integer] Pointer to string that contains distinguished
        #   name of entry to start the search
        # @param scope [Integer] Search Scope
        # @param filter [String] Search Filter
        # @param fields [Array<String>] Attributes to retrieve
        # @return [Hash] Entries found
        def query_ldap(session_handle, base, scope, filter, fields)
          vprint_status('Searching LDAP directory')
          search = wldap32.ldap_search_sA(session_handle, base, scope, filter, nil, 0, 4)
          if search['return'] == LDAP_SIZELIMIT_EXCEEDED
            print_error('LDAP_SIZELIMIT_EXCEEDED, parsing what we retrieved, try increasing the MAX_SEARCH value [0:LDAP_NO_LIMIT]')
          elsif search['return'] != Error::SUCCESS
            print_error("Search returned LDAP error #{search['return']} (#{ERROR_CODE_TO_CONSTANT.fetch(search['return'], 'Unknown')})")
            wldap32.ldap_msgfree(search['res'])
            return
          end

          search_count = wldap32.ldap_count_entries(session_handle, search['res'])['return']

          if search_count == 0
            print_error('No entries retrieved')
            wldap32.ldap_msgfree(search['res'])
            return
          end

          vprint_status("Entries retrieved: #{search_count}")

          if datastore['MAX_SEARCH'] == 0
            max_search = search_count
          else
            max_search = [datastore['MAX_SEARCH'], search_count].min
          end

          entry = wldap32.ldap_first_entry(session_handle, search['res'])['return']

          entry_results = []
          while entry != 0 && (entry_results.length < max_search)
            field_results = []
            fields.each do |field|
              values_result = ''
              values = wldap32.ldap_get_values(session_handle, entry, field)
              if values['return'] != 0
                count_values = wldap32.ldap_count_values(values['return'])
                if count_values['return'] != 0
                  if client.native_arch == ARCH_X64
                    value_pointers = client.railgun.memread(values['return'], 8 * count_values['return']).unpack('Q*')
                  else
                    value_pointers = client.railgun.memread(values['return'], 4 * count_values['return']).unpack('V*')
                  end
                  values_result = value_pointers.map { |ptr| client.railgun.util.read_string(ptr) }.join(',')
                end
                wldap32.ldap_value_free(values['return'])
              end

              field_results << { type: 'unknown', value: values_result }
            end

            entry_results << field_results
            entry = wldap32.ldap_next_entry(session_handle, entry)['return']
          end

          wldap32.ldap_msgfree(search['res'])

          return {
            fields: fields,
            results: entry_results
          }
        end

        # Shortcut to the WLDAP32 Railgun Object
        # @return [Object] wldap32
        def wldap32
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Can't load wldap32: Session doesn't support Railgun!"
          end

          client.railgun.wldap32
        end

        # Binds to the default LDAP Server
        # @param size_limit [Integer] Maximum number of results to return in a query
        # @param domain [String] Optional domain or distinguished name
        # @return LDAP session handle
        def bind_default_ldap_server(size_limit, domain = nil)
          vprint_status('Initializing LDAP connection.')

          # If domain is still null the API may be able to handle it...
          init_result = wldap32.ldap_sslinitA(domain, 389, 0)
          session_handle = init_result['return']
          if session_handle == 0
            raise "Unable to initialize ldap server: #{init_result['ErrorMessage']}"
          end

          vprint_status("LDAP Handle: 0x#{session_handle.to_s(16)}")

          vprint_status('Setting the size limit option')
          wldap32.ldap_set_option(session_handle, LDAP_OPT_SIZELIMIT, [size_limit].pack('V'))

          vprint_status('Binding to LDAP server')
          bind_result = wldap32.ldap_bind_sA(session_handle, nil, nil, LDAP_AUTH_NEGOTIATE)

          bind = bind_result['return']
          unless bind == 0
            wldap32.ldap_unbind(session_handle)
            raise "Unable to bind to ldap server: #{ERROR_CODE_TO_CONSTANT[bind]}"
          end

          if block_given?
            begin
              yield session_handle
            ensure
              vprint_status('Unbinding from LDAP service')
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
