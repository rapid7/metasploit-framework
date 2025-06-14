# -*- coding: binary -*-

module Msf
  class Post
    module Windows
      module Accounts
        include Msf::Post::Windows::Error
        include Msf::Post::Windows::ExtAPI
        include Msf::Post::Windows::Registry

        GUID = [
          ['Data1', :DWORD],
          ['Data2', :WORD],
          ['Data3', :WORD],
          ['Data4', 'BYTE[8]']
        ].freeze

        DOMAIN_CONTROLLER_INFO = [
          ['DomainControllerName', :LPSTR],
          ['DomainControllerAddress', :LPSTR],
          ['DomainControllerAddressType', :ULONG],
          ['DomainGuid', GUID],
          ['DomainName', :LPSTR],
          ['DnsForestName', :LPSTR],
          ['Flags', :ULONG],
          ['DcSiteName', :LPSTR],
          ['ClientSiteName', :LPSTR]
        ].freeze

        GROUP_USERS_INFO = [
          ['grui0_name', :LPWSTR],
        ].freeze

        LOCALGROUP_MEMBERS_INFO = [
          ['lgrmi3_domainandname', :LPWSTR],
        ].freeze

        USER_INFO = [
          ['usri0_name', :LPWSTR],
        ].freeze

        LOCALGROUP_INFO = [
          ['lgrpi0_name', :LPWSTR],
        ].freeze

        GROUP_INFO = [
          ['grpi0_name', :LPWSTR],
        ].freeze

        def initialize(info = {})
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_railgun_api
                    stdapi_railgun_api_multi
                    stdapi_railgun_memread
                    stdapi_railgun_memwrite
                    stdapi_sys_process_attach
                  ]
                }
              }
            )
          )
        end

        # Check if host is an Active Directory domain controller
        #
        # @return [Boolean] Target host is an Active Directory domain controller
        def domain_controller?
          registry_enumkeys('HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS')&.include?('Parameters') ? true : false
        end

        # @return [String] Active Directory primary domain controller FQDN
        def get_primary_domain_controller
          if session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            domain = get_domain('DomainControllerName')
          else
            # Use cached domain controller name
            key = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History'
            return unless registry_key_exist?(key)

            domain = registry_getvaldata(key, 'DCName')
          end

          return unless domain

          domain.gsub(/^\\\\/, '')
        end

        # @return [String] Active Directory domain FQDN
        def get_domain_name
          if session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            return get_domain('DomainName')
          end

          # Use cached domain name
          key = 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History'
          return unless registry_key_exist?(key)

          registry_getvaldata(key, 'MachineDomain')
        end

        ##
        # get_domain(info_key, server_name = nil)
        #
        # Summary:
        #   Retrieves the current DomainName the given server is
        #   a member of.
        #
        # Parameters
        #   server_name - DNS or NetBIOS name of the remote server
        # Returns:
        #   The DomainName of the remote server or nil if windows
        #   could not retrieve the DomainControllerInfo or encountered
        #   an exception.
        #   info_key[
        #   DomainControllerName,
        #   DomainControllerAddress,
        #   DomainControllerAddressType,
        #   DomainGuid,
        #   DomainName,
        #   DcSiteName,
        #   ClientSiteName]
        ##
        def get_domain(info_key = 'DomainName', server_name = nil)
          domain = nil
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            return nil
          end

          result = session.railgun.netapi32.DsGetDcNameA(
            server_name,
            nil,
            nil,
            nil,
            0,
            4
          )

          begin
            dc_info_addr = result['DomainControllerInfo']
            unless dc_info_addr == 0
              dc_info = session.railgun.util.read_data(DOMAIN_CONTROLLER_INFO, dc_info_addr)
              pointer = session.railgun.util.unpack_pointer(dc_info[info_key])
              domain = session.railgun.util.read_string(pointer)
            end
          ensure
            session.railgun.netapi32.NetApiBufferFree(dc_info_addr)
          end

          domain
        end

        ##
        # delete_user(username, server_name = nil)
        #
        # Summary:
        #   Deletes a user account from the given server (or local if none given)
        #
        # Parameters
        #   username    - The username of the user to delete (not-qualified, e.g. BOB)
        #   server_name - DNS or NetBIOS name of remote server on which to delete user
        #
        # Returns:
        #   One of the following:
        #      :success          - Everything went as planned
        #      :invalid_server   - The server name provided was invalid
        #      :not_on_primary   - Operation allowed only on domain controller
        #      :user_not_found   - User specified does not exist on the given server
        #      :access_denied    - You do not have permission to delete the given user
        #
        #   OR nil if there was an exceptional Windows error (example: ran out of memory)
        #
        # Caveats:
        #   nil is returned if there is an *exceptional* Windows error. That error is printed.
        #   Everything other than ':success' signifies failure
        ##
        def delete_user(username, server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            return nil
          end

          deletion = client.railgun.netapi32.NetUserDel(server_name, username)

          # http://msdn.microsoft.com/en-us/library/aa370674.aspx
          case deletion['return']
          when 2221 # NERR_UserNotFound
            return :user_not_found
          when 2351 # NERR_InvalidComputer
            return :invalid_server
          when 2226 # NERR_NotPrimary
            return :not_on_primary
          when client.railgun.const('ERROR_ACCESS_DENIED')
            return :access_denied
          when 0
            return :success
          else
            error = deletion['GetLastError']
            if error != 0
              print_error "Unexpected Windows System Error #{error}"
            else
              # Uh... we shouldn't be here
              print_error "DeleteUser unexpectedly returned #{deletion['return']}"
            end
          end

          # If we got here, then something above failed
          nil
        end

        ##
        # resolve_sid(sid, system_name = nil)
        #
        # Summary:
        #   Retrieves the name, domain, and type of account for the given sid
        #
        # Parameters:
        #   sid         - A SID string (e.g. S-1-5-32-544)
        #   system_name - Where to search. If nil, first local system then trusted DCs
        #
        # Returns:
        #   {
        #     name:   account name (e.g. "SYSTEM")
        #     domain: domain where the account name was found. May have values such as
        #             the work station's name, BUILTIN, NT AUTHORITY, or an empty string
        #     type:   one of :user, :group, :domain, :alias, :well_known_group,
        #             :deleted_account, :invalid, :unknown, :computer
        #     mapped: There was a mapping found for the SID
        #   }
        #
        #   OR nil if there was an exceptional Windows error (example: ran out of memory)
        #
        # Caveats:
        #   If a valid mapping is not found, only { mapped: false } will be returned
        #   nil is returned if there is an *exceptional* Windows error. That error is printed.
        #   If an invalid system_name is provided, there will be a Windows error and nil returned
        ##
        def resolve_sid(sid, system_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            return nil
          end

          adv = client.railgun.advapi32

          # Second param is the size of the buffer where the pointer will be written
          # In railgun, if you specify 4 bytes for a PDWORD it will grow to 8, as needed.
          conversion = adv.ConvertStringSidToSidA(sid, 4)

          # If the call failed, handle errors accordingly.
          unless conversion['return']
            error = conversion['GetLastError']

            case error
            when client.railgun.const('ERROR_INVALID_SID')
              # An invalid SID was supplied
              return { type: :invalid, mapped: false }
            when client.railgun.const('ERROR_NONE_MAPPED')
              # There were no accounts associated with this SID
              return { mapped: false }
            else
              print_error "Unexpected Windows error #{error} resolving SID #{sid}"
              return nil
            end
          end

          psid = conversion['pSid']

          # Begin/Ensure so we free the pSid buffer...
          begin
            # A reference to the SID data structure. Generally needed when working with sids

            # http://msdn.microsoft.com/en-us/library/aa379166(v=vs.85).aspx
            lp_name = lp_referenced_domain_name = 100
            cch_name = cch_referenced_domain_name = 100
            lookup = adv.LookupAccountSidA(
              system_name,
              psid,
              lp_name,
              cch_name,
              lp_referenced_domain_name,
              cch_referenced_domain_name,
              1
            )

            if !lookup['return'] && lookup['GetLastError'] == INSUFFICIENT_BUFFER
              lp_name = cch_name = lookup['cchName']
              lp_referenced_domain_name = cch_referenced_domain_name = lookup['cchReferencedDomainName']

              lookup = adv.LookupAccountSidA(
                system_name,
                psid,
                lp_name,
                cch_name,
                lp_referenced_domain_name,
                cch_referenced_domain_name,
                1
              )

            elsif !lookup['return']
              print_error "Unexpected Windows error #{lookup['GetLastError']}"
              return nil
            end
          ensure
            # We no longer need the sid so free it.
            adv.FreeSid(psid)
          end

          # If the call failed, handle errors accordingly.
          unless lookup['return']
            error = lookup['GetLastError']

            case error
            when client.railgun.const('ERROR_INVALID_PARAMETER')
              # Unless the railgun call is broken, this means revision is wrong
              return { type: :invalid }
            when client.railgun.const('ERROR_NONE_MAPPED')
              # There were no accounts associated with this SID
              return { mapped: false }
            else
              print_error "Unexpected Windows error #{error} resolving SID #{sid}"
              return nil
            end
          end

          # peUse is the enum "SID_NAME_USE"
          sid_type = lookup_sid_name_use(lookup['peUse'].unpack1('C'))

          return {
            name: lookup['Name'],
            domain: lookup['ReferencedDomainName'],
            type: sid_type,
            mapped: true
          }
        end

        private

        ##
        # Converts a WinAPI's SID_NAME_USE enum to a symbol
        # Symbols are (in order) :user, :group, :domain, :alias, :well_known_group,
        #                        :deleted_account, :invalid, :unknown, :computer
        ##
        def lookup_sid_name_use(enum_value)
          [
            # SidTypeUser = 1
            :user,
            # SidTypeGroup,
            :group,
            # SidTypeDomain,
            :domain,
            # SidTypeAlias,
            :alias,
            # SidTypeWellKnownGroup,
            :well_known_group,
            # SidTypeDeletedAccount,
            :deleted_account,
            # SidTypeInvalid,
            :invalid,
            # SidTypeUnknown,
            :unknown,
            # SidTypeComputer,
            :computer,
            # SidTypeLabel
            :integrity_label
          ][enum_value - 1]
        end

        # Gets an impersonation token from the primary token.
        #
        # @return [Integer] the impersonate token handle identifier if success, nil if
        #  fails
        def get_imperstoken
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          adv = session.railgun.advapi32
          tok_all = 'TOKEN_ASSIGN_PRIMARY |TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | '
          tok_all << 'TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS'
          tok_all << ' | TOKEN_ADJUST_DEFAULT'

          pid = session.sys.process.open.pid
          pr = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
          pt = adv.OpenProcessToken(pr.handle, tok_all, 4) # get handle to primary token
          it = adv.DuplicateToken(pt['TokenHandle'], 2, 4) # get an impersonation token
          if it['return'] # if it fails return 0 for error handling
            return it['DuplicateTokenHandle']
          else
            return nil
          end
        end

        # Gets the permissions granted from the Security Descriptor of a directory
        # to an access token.
        #
        # @param [String] dir the directory path
        # @param [Integer] token the access token
        # @return [String, nil] a String describing the permissions or nil
        def check_dir_perms(dir, token)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          adv = session.railgun.advapi32
          si = 'OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION'
          result = ''

          # define generic mapping structure
          gen_map = [0, 0, 0, 0]
          gen_map = gen_map.pack('V')
          buffer_size = 500

          # get Security Descriptor for the directory
          f = adv.GetFileSecurityA(dir, si, buffer_size, buffer_size, 4)
          if f['return'] && f['lpnLengthNeeded'] <= buffer_size
            sd = f['pSecurityDescriptor']
          elsif f['GetLastError'] == 122 # ERROR_INSUFFICIENT_BUFFER
            sd = adv.GetFileSecurityA(dir, si, f['lpnLengthNeeded'], f['lpnLengthNeeded'], 4)
          elsif f['GetLastError'] == 2
            vprint_error("The system cannot find the file specified: #{dir}")
            return nil
          else
            vprint_error("#{f['ErrorMessage']}: #{dir}")
            return nil
          end

          # check for write access, called once to get buffer size
          a = adv.AccessCheck(sd, token, 'ACCESS_READ | ACCESS_WRITE', gen_map, 0, 0, 4, 8)
          len = a['PrivilegeSetLength']

          r = adv.AccessCheck(sd, token, 'ACCESS_READ', gen_map, len, len, 4, 8)
          return nil if !r['return']

          result << 'R' if r['GrantedAccess'] > 0

          w = adv.AccessCheck(sd, token, 'ACCESS_WRITE', gen_map, len, len, 4, 8)
          return nil if !w['return']

          result << 'W' if w['GrantedAccess'] > 0

          result
        end

        ##
        # add_user(username, password, server_name = nil)
        #
        # Summary:
        #   Adds a user account to the given server (or local, if none specified)
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        #   username    - The username of the account to add (not-qualified, e.g. BOB)
        #   password    - The password to be assigned to the new user account
        ##
        def add_user(username, password, server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          addr_username = session.railgun.util.alloc_and_write_wstring(username)
          addr_password = session.railgun.util.alloc_and_write_wstring(password)
          #  Set up the USER_INFO_1 structure.
          #  https://docs.microsoft.com/en-us/windows/win32/api/Lmaccess/ns-lmaccess-user_info_1
          user_info = [
            addr_username,
            addr_password,
            0x0,
            0x1,
            0x0,
            0x0,
            client.railgun.const('UF_SCRIPT | UF_NORMAL_ACCOUNT|UF_DONT_EXPIRE_PASSWD'),
            0x0
          ].pack(client.arch == ARCH_X86 ? 'VVVVVVVV' : 'QQVVQQVQ')
          result = client.railgun.netapi32.NetUserAdd(server_name, 1, user_info, 4)
          session.railgun.util.free_data(addr_username, addr_password)
          return result
        end

        ##
        # add_localgroup(localgroup, server_name = nil,)
        #
        # Summary:
        #   Creates a local group to the given server (or local, if none specified)
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        #   localgroup  - Specifies a local group name
        ##
        def add_localgroup(localgroup, server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          #  Set up the #  LOCALGROUP_INFO_1 structure.
          addr_group = session.railgun.util.alloc_and_write_wstring(localgroup)
          #  https://docs.microsoft.com/windows/desktop/api/lmaccess/ns-lmaccess-localgroup_info_1
          localgroup_info = [
            addr_group, #  lgrpi1_name
            0x0 #  lgrpi1_comment
          ].pack(client.arch == ARCH_X86 ? 'VV' : 'QQ')
          result = client.railgun.netapi32.NetLocalGroupAdd(server_name, 1, localgroup_info, 4)
          session.railgun.util.free_data(addr_group)
          return result
        end

        # add_group(group, server_name = nil)
        #
        # Summary:
        #    Creates a global group in the security database,
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        #   group       - Specifies a global group name
        ##
        def add_group(group, server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          addr_group = session.railgun.util.alloc_and_write_wstring(group)
          #  https://docs.microsoft.com/zh-cn/windows/win32/api/lmaccess/ns-lmaccess-group_info_1
          # Set up the GROUP_INFO_1 structure.
          group_info_1 = [
            addr_group,
            0x0
          ].pack(client.arch == ARCH_X86 ? 'VV' : 'QQ')
          result = client.railgun.netapi32.NetGroupAdd(server_name, 1, group_info_1, 4)
          session.railgun.util.free_data(addr_group)
          return result
        end

        # add_members_localgroup(localgroup, username, server_name = nil)
        #
        # Summary:
        #    Adds membership of one existing user accounts or global group accounts to an existing local group.
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        #   localgroup  - Specifies a local group name
        #   username    - Specifies a local username
        ##
        def add_members_localgroup(localgroup, username, server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          addr_username = session.railgun.util.alloc_and_write_wstring(username)
          #  Set up the LOCALGROUP_MEMBERS_INFO_3 structure.
          #  https://docs.microsoft.com/windows/desktop/api/lmaccess/ns-lmaccess-localgroup_members_info_3
          localgroup_members = [
            addr_username,
          ].pack(client.arch == ARCH_X86 ? 'V' : 'Q')
          result = client.railgun.netapi32.NetLocalGroupAddMembers(server_name, localgroup, 3, localgroup_members, 1)
          session.railgun.util.free_data(addr_username)
          return result
        end

        # add_members_group(group, username, server_name = nil)
        #
        # Summary:
        #    Gives an existing user account membership in an existing global group in the security database
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        #   group       - Specifies a global group name
        #   username    - Specifies a global username
        ##
        def add_members_group(group, username, server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          result = client.railgun.netapi32.NetGroupAddUser(server_name, group, username)
          return result
        end

        # get_members_from_group(groupname, server_name = nil)
        #
        # Summary:
        #    retrieves a list of the members in a particular global group in the security database.
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        #   group       - Specifies a group name
        ##
        def get_members_from_group(groupname, server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          members = []
          result = client.railgun.netapi32.NetGroupGetUsers(server_name, groupname, 0, 4, 4096, 4, 4, 0)
          if (result['return'] == 0) && ((result['totalentries'] % 4294967296) != 0)
            begin
              members_info_addr = result['bufptr']
              unless members_info_addr == 0
                # Railgun assumes PDWORDS are pointers and returns 8 bytes for x64 architectures.
                # Therefore we need to truncate the result value to an actual
                # DWORD for entriesread or totalentries.
                members_info = session.railgun.util.read_array(GROUP_USERS_INFO, (result['totalentries'] % 4294967296), members_info_addr)
                for member in members_info
                  members << member['grui0_name']
                end
                return members
              end
            end
          else
            return members
          end
        ensure
          session.railgun.netapi32.NetApiBufferFree(members_info_addr)
        end

        # get_members_from_localgroup(groupname, server_name = nil)
        #
        # Summary:
        #    retrieves a list of the members in a particular local group in the security database.
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        #   group       - Specifies a group name
        ##
        def get_members_from_localgroup(localgroupname, server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          members = []
          result = client.railgun.netapi32.NetLocalGroupGetMembers(server_name, localgroupname, 3, 4, 4096, 4, 4, 0)
          if (result['return'] == 0) && ((result['totalentries'] % 4294967296) != 0)
            begin
              members_info_addr = result['bufptr']
              unless members_info_addr == 0
                members_info = session.railgun.util.read_array(LOCALGROUP_MEMBERS_INFO, (result['totalentries'] % 4294967296), members_info_addr)
                for member in members_info
                  members << member['lgrmi3_domainandname']
                end
                return members
              end
            end
          else
            return members
          end
        ensure
          session.railgun.netapi32.NetApiBufferFree(members_info_addr)
        end

        # enum_user(groupname, server_name = nil)
        #
        # Summary:
        #    provides information about all user accounts on a server.
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        ##
        def enum_user(server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          users = []
          filter = 'FILTER_NORMAL_ACCOUNT|FILTER_TEMP_DUPLICATE_ACCOUNT'
          result = client.railgun.netapi32.NetUserEnum(server_name, 0, client.railgun.const(filter), 4, 4096, 4, 4, 0)
          if (result['return'] == 0) && ((result['totalentries'] % 4294967296) != 0)
            begin
              user_info_addr = result['bufptr']
              unless user_info_addr == 0
                user_info = session.railgun.util.read_array(USER_INFO, (result['totalentries'] % 4294967296), user_info_addr)
                for member in user_info
                  users << member['usri0_name']
                end
                return users
              end
            end
          else
            return users
          end
        ensure
          session.railgun.netapi32.NetApiBufferFree(user_info_addr)
        end

        # enum_localgroup(server_name = nil)
        #
        # Summary:
        #    returns information about each local group account on the specified server.
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        ##
        def enum_localgroup(server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          localgroups = []
          result = client.railgun.netapi32.NetLocalGroupEnum(server_name, 0, 4, 4096, 4, 4, 0)
          if (result['return'] == 0) && ((result['totalentries'] % 4294967296) != 0)
            begin
              localgroup_info_addr = result['bufptr']
              unless localgroup_info_addr == 0
                localgroup_info = session.railgun.util.read_array(LOCALGROUP_INFO, (result['totalentries'] % 4294967296), localgroup_info_addr)
                for member in localgroup_info
                  localgroups << member['lgrpi0_name']
                end
                return localgroups
              end
            end
          else
            return localgroups
          end
        ensure
          session.railgun.netapi32.NetApiBufferFree(localgroup_info_addr)
        end

        # enum_group(server_name = nil)
        #
        # Summary:
        #    retrieves information about each global group in the security database.
        #
        # Parameters
        #   server_name - The DNS or NetBIOS name of the remote server on which the function is to execute.
        ##
        def enum_group(server_name = nil)
          unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)
            raise "Session doesn't support Railgun!"
          end

          groups = []
          result = client.railgun.netapi32.NetGroupEnum(server_name, 0, 4, 4096, 4, 4, 0)
          if (result['return'] == 0) && ((result['totalentries'] % 4294967296) != 0)
            begin
              group_info_addr = result['bufptr']
              unless group_info_addr == 0
                group_info = session.railgun.util.read_array(GROUP_INFO, (result['totalentries'] % 4294967296), group_info_addr)
                for member in group_info
                  groups << member['grpi0_name']
                end
                return groups
              end
            end
          else
            return groups
          end
        ensure
          session.railgun.netapi32.NetApiBufferFree(group_info_addr)
        end
      end # Accounts
    end # Windows
  end # Post
end # Msf
