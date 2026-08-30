# -*- coding: binary -*-

require 'rex/proto/ms_dtyp'

module Msf
  class Post
    module Windows
      module Lsa
        def initialize(info = {})
          super(
            update_info(
              info,
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

        # [UNICODE_STRING structure (subauth.h)](https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string)
        class UNICODE_STRING_x64 < BinData::Record
          endian :little

          uint16 :len
          uint16 :maximum_len
          uint64 :buffer, byte_align: 8
        end

        # [UNICODE_STRING structure (subauth.h)](https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string)
        class UNICODE_STRING_x86 < BinData::Record
          endian :little

          uint16 :len
          uint16 :maximum_len
          uint32 :buffer, byte_align: 4
        end

        # [LSA_LAST_INTER_LOGON_INFO structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-lsa_last_inter_logon_info)
        class LSA_LAST_INTER_LOGON_INFO < BinData::Record
          endian :little
          search_prefix :ms_dtyp

          large_integer :last_successful_logon
          large_integer :last_failed_logon
          uint32        :failed_attempt_count_since_last_successful_logon
        end

        # [LSA_STRING structure (lsalookup.h)](https://learn.microsoft.com/en-us/windows/win32/api/lsalookup/ns-lsalookup-lsa_string)
        class LSA_STRING_x64 < BinData::Record
          endian :little

          uint16 :len
          uint16 :maximum_len
          uint64 :buffer, byte_align: 8
        end

        # [LSA_STRING structure (lsalookup.h)](https://learn.microsoft.com/en-us/windows/win32/api/lsalookup/ns-lsalookup-lsa_string)
        class LSA_STRING_x86 < BinData::Record
          endian :little

          uint16 :len
          uint16 :maximum_len
          uint32 :buffer, byte_align: 4
        end

        # [LSA_UNICODE_STRING structure (lsalookup.h)](https://learn.microsoft.com/en-us/windows/win32/api/lsalookup/ns-lsalookup-lsa_unicode_string)
        class LSA_UNICODE_STRING_x64 < BinData::Record
          endian :little

          uint16 :len
          uint16 :maximum_len
          uint64 :buffer, byte_align: 8
        end

        # [LSA_UNICODE_STRING structure (lsalookup.h)](https://learn.microsoft.com/en-us/windows/win32/api/lsalookup/ns-lsalookup-lsa_unicode_string)
        class LSA_UNICODE_STRING_x86 < BinData::Record
          endian :little

          uint16 :len
          uint16 :maximum_len
          uint32 :buffer, byte_align: 4
        end

        # [KERB_CRYPTO_KEY structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_crypto_key)
        class KERB_CRYPTO_KEY_x64 < BinData::Record
          endian :little

          int32  :key_type
          uint32 :len
          uint64 :val
        end

        # [KERB_CRYPTO_KEY structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_crypto_key)
        class KERB_CRYPTO_KEY_x86 < BinData::Record
          endian :little

          int32  :key_type
          uint32 :len
          uint32 :val
        end

        # [KERB_EXTERNAL_TICKET](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_external_ticket)
        class KERB_EXTERNAL_TICKET_x64 < BinData::Record
          endian :little
          search_prefix :ms_dtyp

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

        # [KERB_EXTERNAL_TICKET](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_external_ticket)
        class KERB_EXTERNAL_TICKET_x86 < BinData::Record
          endian :little
          search_prefix :ms_dtyp

          uint32              :service_name
          uint32              :target_name
          uint32              :client_name
          unicode_string_x86  :domain_name
          unicode_string_x86  :target_domain_name
          unicode_string_x86  :alt_target_domain_name
          kerb_crypto_key_x86 :session_key
          uint32              :ticket_flags
          uint32              :flags
          large_integer       :key_expiration_time
          large_integer       :start_time
          large_integer       :end_time
          large_integer       :renew_until
          large_integer       :time_skew
          uint32              :encoded_ticket_size
          uint32              :encoded_ticket, byte_align: 4
        end

        # https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Authentication/Identity/struct.KERB_TICKET_CACHE_INFO_EX.html
        class KERB_TICKET_CACHE_INFO_EX_x64 < BinData::Record
          endian :little
          search_prefix :ms_dtyp

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

        # https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Authentication/Identity/struct.KERB_TICKET_CACHE_INFO_EX.html
        class KERB_TICKET_CACHE_INFO_EX_x86 < BinData::Record
          endian :little
          search_prefix :ms_dtyp

          lsa_unicode_string_x86 :client_name
          lsa_unicode_string_x86 :client_realm
          lsa_unicode_string_x86 :server_name
          lsa_unicode_string_x86 :server_realm
          large_integer          :start_time
          large_integer          :end_time
          large_integer          :renew_time
          int32                  :encryption_type
          uint32                 :ticket_flags
        end

        # [KERB_QUERY_TKT_CACHE_REQUEST structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_query_tkt_cache_request)
        class KERB_QUERY_TKT_CACHE_REQUEST < BinData::Record
          endian :little
          search_prefix :ms_dtyp

          uint32 :message_type
          luid   :logon_id
        end

        # [KERB_QUERY_TKT_CACHE_RESPONSE structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_query_tkt_cache_response)
        class KERB_QUERY_TKT_CACHE_RESPONSE_x64 < BinData::Record
          endian :little

          uint32 :message_type
          uint32 :count_of_tickets
          array  :tickets, type: :kerb_ticket_cache_info_ex_x64, initial_length: :count_of_tickets
        end

        # [KERB_QUERY_TKT_CACHE_RESPONSE structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_query_tkt_cache_response)
        class KERB_QUERY_TKT_CACHE_RESPONSE_x86 < BinData::Record
          endian :little

          uint32 :message_type
          uint32 :count_of_tickets
          array  :tickets, type: :kerb_ticket_cache_info_ex_x86, initial_length: :count_of_tickets
        end

        # [KERB_RETRIEVE_TKT_REQUEST structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_retrieve_tkt_request)
        class KERB_RETRIEVE_TKT_REQUEST_x64 < BinData::Record
          endian :little
          search_prefix :ms_dtyp

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

        # [KERB_RETRIEVE_TKT_REQUEST structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_retrieve_tkt_request)
        class KERB_RETRIEVE_TKT_REQUEST_x86 < BinData::Record
          endian :little
          search_prefix :ms_dtyp

          uint32                 :message_type
          luid                   :logon_id
          lsa_unicode_string_x86 :target_name, byte_align: 4
          uint32                 :ticket_flags
          uint32                 :cache_options
          int32                  :encryption_type
          struct                 :credentials_handle, byte_align: 4 do # SecHandle, see: https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sechandle
            uint64               :dw_lower
            uint64               :dw_upper
          end
        end

        # [KERB_RETRIEVE_TKT_RESPONSE structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_retrieve_tkt_response)
        class KERB_RETRIEVE_TKT_RESPONSE_x64 < BinData::Record
          endian :little

          kerb_external_ticket_x64 :ticket
        end

        # [KERB_RETRIEVE_TKT_RESPONSE structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_retrieve_tkt_response)
        class KERB_RETRIEVE_TKT_RESPONSE_x86 < BinData::Record
          endian :little

          kerb_external_ticket_x86 :ticket
        end

        # [SECURITY_LOGON_SESSION_DATA structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-security_logon_session_data)
        class SECURITY_LOGON_SESSION_DATA_x64 < BinData::Record
          endian :little
          search_prefix :ms_dtyp

          uint32                    :len
          luid                      :logon_id
          lsa_unicode_string_x64    :user_name, byte_align: 8
          lsa_unicode_string_x64    :logon_domain
          lsa_unicode_string_x64    :authentication_package
          uint32                    :logon_type
          uint32                    :session
          uint64                    :psid
          large_integer             :logon_time
          lsa_unicode_string_x64    :logon_server
          lsa_unicode_string_x64    :dns_domain_name
          lsa_unicode_string_x64    :upn
          uint32                    :user_flags
          lsa_last_inter_logon_info :last_logon_info, byte_align: 8
          lsa_unicode_string_x64    :logon_script
          lsa_unicode_string_x64    :profile_path
          lsa_unicode_string_x64    :home_directory
          lsa_unicode_string_x64    :home_directory_drive
          large_integer             :logoff_time
          large_integer             :kick_off_time
          large_integer             :password_last_set
          large_integer             :password_can_change
          large_integer             :password_must_change
        end

        # [SECURITY_LOGON_SESSION_DATA structure (ntsecapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-security_logon_session_data)
        class SECURITY_LOGON_SESSION_DATA_x86 < BinData::Record
          endian :little
          search_prefix :ms_dtyp

          uint32                    :len
          luid                      :logon_id
          lsa_unicode_string_x86    :user_name, byte_align: 4
          lsa_unicode_string_x86    :logon_domain
          lsa_unicode_string_x86    :authentication_package
          uint32                    :logon_type
          uint32                    :session
          uint32                    :psid
          large_integer             :logon_time
          lsa_unicode_string_x86    :logon_server
          lsa_unicode_string_x86    :dns_domain_name
          lsa_unicode_string_x86    :upn
          uint32                    :user_flags
          lsa_last_inter_logon_info :last_logon_info, byte_align: 4
          lsa_unicode_string_x86    :logon_script
          lsa_unicode_string_x86    :profile_path
          lsa_unicode_string_x86    :home_directory
          lsa_unicode_string_x86    :home_directory_drive
          large_integer             :logoff_time
          large_integer             :kick_off_time
          large_integer             :password_last_set
          large_integer             :password_can_change
          large_integer             :password_must_change
        end

        # [TOKEN_STATISTICS structure (winnt.h)](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics)
        class TOKEN_STATISTICS < BinData::Record
          endian :little
          search_prefix :ms_dtyp

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

        LsaPointer = Struct.new(:value, :contents)

        # Initialize a new LSA_STRING instance in memory.
        #
        # @param [String] string The string value to place in memory.
        def lsa_string(string)
          case session.native_arch
          when ARCH_X64
            klass = LSA_STRING_x64
          when ARCH_X86
            klass = LSA_STRING_x86
          else
            raise NotImplementedError, "Unsupported session architecture: #{session.native_arch}"
          end

          ptr = session.railgun.util.alloc_and_write_string(string)
          return nil if ptr.nil?

          klass.new(len: string.length, maximum_len: string.length + 1, buffer: ptr)
        end

        # Initialize a new LSA_UNICODE_STRING instance in memory.
        #
        # @param [String] string The string value to place in memory.
        def lsa_unicode_string(string)
          case session.native_arch
          when ARCH_X64
            klass = LSA_UNICODE_STRING_x64
          when ARCH_X86
            klass = LSA_UNICODE_STRING_x86
          else
            raise NotImplementedError, "Unsupported session architecture: #{session.native_arch}"
          end

          ptr = session.railgun.util.alloc_and_write_string(string)
          return nil if ptr.nil?

          klass.new(len: string.length, maximum_len: string.length + 2, buffer: ptr)
        end

        # Read an LSA_UNICODE_STRING from memory.
        #
        # @param [LSA_UNICODE_STRING] str The LSA_UNICODE_STRING to read from memory.
        def read_lsa_unicode_string(str)
          return '' if str.len == 0

          # the len field is in bytes, divide by two because #read_wstring takes chars
          session.railgun.util.read_wstring(str.buffer, str.len / 2)
        end

        def lsa_call_authentication_package(handle, auth_package, submit_buffer, submit_buffer_length: nil)
          if auth_package.is_a?(String)
            auth_package = lsa_lookup_authentication_package(handle, auth_package)
            return nil if auth_package.nil?
          end

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
            print_error("Failed to call the authentication package. LsaCallAuthenticationPackage failed with: #{status}")
            return nil
          end
          unless result['ProtocolStatus'] == ::WindowsError::NTStatus::STATUS_SUCCESS
            status = lsa_nt_status_to_win_error(result['ProtocolStatus'])
            print_error("Failed to call the authentication package. LsaCallAuthenticationPackage authentication package failed with: #{status}")
            return nil
          end
          return nil if result['ProtocolReturnBuffer'] == 0

          LsaPointer.new(result['ProtocolReturnBuffer'], session.railgun.memread(result['ProtocolReturnBuffer'], result['ReturnBufferLength']))
        end

        def lsa_connect_untrusted
          result = session.railgun.secur32.LsaConnectUntrusted(4)
          unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS
            status = ::WindowsError::NTStatus.find_by_retval(result['return']).first
            print_error("Failed to obtain a handle to LSA. LsaConnectUntrusted failed with: #{status.to_s}")
            return nil
          end

          result['LsaHandle']
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

        def lsa_enumerate_logon_sessions
          result = session.railgun.secur32.LsaEnumerateLogonSessions(4, 4)
          unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS
            status = ::WindowsError::NTStatus.find_by_retval(result['return']).first
            print_error("Failed to enumerate logon sessions. LsaEnumerateLogonSessions failed with: #{status.to_s}")
            return nil
          end

          return [] if result['LogonSessionCount'] == 0
          luids = BinData::Array.new(type: :ms_dtyp_luid, initial_length: result['LogonSessionCount'])
          luids.read(session.railgun.memread(result['LogonSessionList'], luids.num_bytes))
          session.railgun.secur32.LsaFreeReturnBuffer(result['LogonSessionList'])
          luids
        end

        def lsa_get_logon_session_data(luid)
          case session.native_arch
          when ARCH_X64
            logon_session_data = SECURITY_LOGON_SESSION_DATA_x64.new
            result = session.railgun.secur32.LsaGetLogonSessionData(luid, 8)
          when ARCH_X86
            logon_session_data = SECURITY_LOGON_SESSION_DATA_x86.new
            result = session.railgun.secur32.LsaGetLogonSessionData(luid, 4)
          else
            raise NotImplementedError, "Unsupported session architecture: #{session.native_arch}"
          end

          unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS
            status = ::WindowsError::NTStatus.find_by_retval(result['return']).first
            print_error("Failed to obtain logon session data. LsaGetLogonSessionData failed with: #{status.to_s}")
            return nil
          end
          logon_session_data.read(session.railgun.memread(result['ppLogonSessionData'], logon_session_data.num_bytes))

          LsaPointer.new(result['ppLogonSessionData'], logon_session_data)
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

        def lsa_nt_status_to_win_error(nt_status)
          ::WindowsError::Win32.find_by_retval(session.railgun.advapi32.LsaNtStatusToWinError(nt_status)['return']).first
        end

        def lsa_register_logon_process
          logon_process_name = lsa_string('Winlogon')
          return nil if logon_process_name.nil?

          result = session.railgun.secur32.LsaRegisterLogonProcess(logon_process_name.to_binary_s, 4, 4)
          session.railgun.util.free_string(logon_process_name.buffer)
          unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS
            status = ::WindowsError::NTStatus.find_by_retval(result['return']).first
            print_error("Failed to obtain a handle to LSA. LsaRegisterLogonProcess failed with: #{status.to_s}")
            return nil
          end

          result['LsaHandle']
        end
      end
    end
  end
end
