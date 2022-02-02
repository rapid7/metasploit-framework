# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      module Pac
        # @todo Make more fields user controllable, instead of constants.
        # This class provides a representation of a PAC_LOGON_INFO structure, which contains the
        # credential information for the client of the Kerberos ticket.
        class LogonInfo < Element

          # @!attribute logon_time
          #   @return [Time] The time the client last logged on
          attr_accessor :logon_time
          # @!attribute effective_name
          #   @return [String] The client's Windows 2000 user name
          attr_accessor :effective_name
          # @!attribute user_id
          #   @return [Integer] The relative ID for the client
          attr_accessor :user_id
          # @!attribute primary_group_id
          #   @return [Integer] The relative ID for the client's primary group
          attr_accessor :primary_group_id
          # @!attribute group_ids
          #   @return [Array<Integer>] Array of relative Ids of the groups which the client is a member
          attr_accessor :group_ids
          # @!attribute logon_domain_name
          #   @return [String] The netbios name of the client's domain
          attr_accessor :logon_domain_name
          # @!attribute logon_domain_sid
          #   @return [String] The SID of the client's domain
          attr_accessor :logon_domain_id

          # Encodes the Rex::Proto::Kerberos::Pac::LogonInfo
          #
          # @return [String]
          def encode
            elements = []
            elements[0] = ''
            elements[0] << encode_element_id
            elements[0] << encode_logon_time
            elements[0] << encode_logoff_time
            elements[0] << encode_kickoff_time
            elements[0] << encode_password_last_set
            elements[0] << encode_password_can_change
            elements[0] << encode_password_must_change
            elements[0] << encode_effective_name
            elements << encode_effective_name_info
            elements[0] << encode_full_name
            elements << encode_full_name_info
            elements[0] << encode_logon_script
            elements << encode_logon_script_info
            elements[0] << encode_profile_path
            elements << encode_profile_path_info
            elements[0] << encode_home_directory
            elements << encode_home_directory_info
            elements[0] << encode_home_directory_drive
            elements << encode_home_directory_drive_info
            elements[0] << encode_logon_count
            elements[0] << encode_bad_password_count
            elements[0] << encode_user_id
            elements[0] << encode_primary_group_id
            elements[0] << encode_group_count
            elements[0] << encode_group_ids
            elements << encode_group_ids_info
            elements[0] << encode_user_flags
            elements[0] << encode_user_session_key
            elements[0] << encode_logon_server
            elements << encode_logon_server_info
            elements[0] << encode_logon_domain_name
            elements << encode_logon_domain_name_info
            elements[0] << encode_logon_domain_id
            elements << encode_logon_domain_id_info
            elements[0] << encode_reserved_one
            elements[0] << encode_user_account_control
            elements[0] << encode_reserved_three
            elements[0] << encode_sid_count
            elements[0] << encode_extra_sids
            elements[0] << encode_resource_group_domain_sid
            elements[0] << encode_resource_group_count
            elements[0] << encode_resource_group_ids

            decoded = ''
            elements.each do |elem|
              decoded << elem
              decoded << "\x00" * ((elem.length + 3) / 4 * 4 - elem.length)
            end

            header = "\x01\x10\x08\x00\xcc\xcc\xcc\xcc"
            header << [decoded.length, 0].pack('VV')

            header + decoded
          end

          private

          # Encodes the netlogon type
          #
          # @return [String]
          def encode_element_id
            [NETLOGON_FLAG].pack('V')
          end

          # Encodes the logon_time attribute
          #
          # @return [String]
          def encode_logon_time
            file_time = (logon_time.to_i + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK
            encoded = ''
            encoded << [file_time].pack('Q<')

            encoded
          end

          # Encodes the logoff time (constant)
          #
          # @return [String]
          def encode_logoff_time
            [NEVER_EXPIRE].pack('Q<')
          end

          # Encodes the kickoff time (constant)
          #
          # @return [String]
          def encode_kickoff_time
            [NEVER_EXPIRE].pack('Q<')
          end

          # Encodes the password_last_set (constant)
          #
          # @return [String]
          def encode_password_last_set
            [0].pack('Q<')
          end

          # Encodes the password_can_change (constant)
          #
          # @return [String]
          def encode_password_can_change
            [0].pack('Q<')
          end

          # Encodes the password_must_change (constant)
          #
          # @return [String]
          def encode_password_must_change
            [NEVER_EXPIRE].pack('Q<')
          end

          # Encodes the effective_name id field
          #
          # @return [String]
          def encode_effective_name
            unicode = Rex::Text.to_unicode(effective_name)

            encoded = ''
            encoded << [
              unicode.length,
              unicode.length,
              0x20004
            ].pack('vvV')

            encoded
          end

          # Encodes the effective_name info field
          #
          # @return [String]
          def encode_effective_name_info
            unicode = Rex::Text.to_unicode(effective_name)

            encoded = ''
            encoded << [
              effective_name.length,
              effective_name.length
            ].pack('Q<V')
            encoded << unicode
          end

          # Encodes the full_name id
          #
          # @return [String]
          def encode_full_name
            unicode = Rex::Text.to_unicode('')
            encoded = ''
            encoded << [
              unicode.length,
              unicode.length,
              0x20008
            ].pack('vvV')

            encoded
          end

          # Encodes the full_name_info (constant)
          #
          # @return [String]
          def encode_full_name_info
            unicode = Rex::Text.to_unicode('')
            encoded = ''
            encoded << [
              ''.length,
              ''.length
            ].pack('Q<V')
            encoded << unicode
            encoded
          end

          # Encodes the logon_script id
          #
          # @return [String]
          def encode_logon_script
            unicode = Rex::Text.to_unicode('')

            encoded = ''
            encoded << [
              unicode.length,
              unicode.length,
              0x2000c
            ].pack('vvV')

            encoded
          end

          # Encodes the logon_script info (constant)
          #
          # @return [String]
          def encode_logon_script_info
            unicode = Rex::Text.to_unicode('')
            encoded = ''
            encoded << [
              ''.length,
              ''.length
            ].pack('Q<V')
            encoded << unicode

            encoded
          end

          # Encodes the profile_path id
          #
          # @return [String]
          def encode_profile_path
            unicode = Rex::Text.to_unicode('')

            encoded = ''
            encoded << [
              unicode.length,
              unicode.length,
              0x20010
            ].pack('vvV')

            encoded
          end

          # Encodes the profile_path info (constant)
          #
          # @return [String]
          def encode_profile_path_info
            unicode = Rex::Text.to_unicode('')
            encoded = ''
            encoded << [
              ''.length,
              ''.length
            ].pack('Q<V')
            encoded << unicode

            encoded
          end

          # Encodes the home_directory id
          #
          # @return [String]
          def encode_home_directory
            unicode = Rex::Text.to_unicode('')

            encoded = ''
            encoded << [
              unicode.length,
              unicode.length,
              0x20014
            ].pack('vvV')

            encoded
          end

          # Encodes the home_directory info (constant)
          #
          # @return [String]
          def encode_home_directory_info
            unicode = Rex::Text.to_unicode('')
            encoded = ''
            encoded << [
                ''.length,
                ''.length
            ].pack('Q<V')
            encoded << unicode

            encoded
          end

          # Encodes hte home_directory_drive id
          #
          # @return [String]
          def encode_home_directory_drive
            unicode = Rex::Text.to_unicode('')

            encoded = ''
            encoded << [
              unicode.length,
              unicode.length,
              0x20018
            ].pack('vvV')
            encoded
          end

          # Encodes the home_directory_drive info (constant)
          #
          # @return [String]
          def encode_home_directory_drive_info
            unicode = Rex::Text.to_unicode('')
            encoded = ''
            encoded << [
                ''.length,
                ''.length
            ].pack('Q<V')
            encoded << unicode

            encoded
          end

          # Encodes the logon_count (constant)
          #
          # @return [String]
          def encode_logon_count
            [0].pack('v')
          end

          # Encodes the bad_password_count (constant)
          #
          # @return [String]
          def encode_bad_password_count
            [0].pack('v')
          end

          # Encodes the user_id field
          #
          # @return [String]
          def encode_user_id
            [user_id].pack('V')
          end

          # Encodes the primary_group_id field
          #
          # @return [String]
          def encode_primary_group_id
            [primary_group_id].pack('V')
          end

          # Encodes the group_count field
          #
          # @return [String]
          def encode_group_count
            [group_ids.length].pack('V')
          end

          # Encodes the group_ids id
          #
          # @return [String]
          def encode_group_ids
            encoded = ''
            encoded << [0x2001c].pack('V')

            encoded
          end

          # Encodes the group_ids info
          #
          # @return [String]
          def encode_group_ids_info
            encoded = ''
            encoded << [group_ids.length].pack('V')
            group_ids.each do |group|
              encoded << [
                group,
                SE_GROUP_ALL
              ].pack('VV')
            end

            encoded
          end

          # Encodes the user_flags (constant)
          #
          # @return [String]
          def encode_user_flags
            [0].pack('V')
          end

          # Encodes the user_session_key (constant)
          #
          # @return [String]
          def encode_user_session_key
            [0, 0].pack('Q<Q<')
          end

          # Encodes the logon_server id
          #
          # @return [String]
          def encode_logon_server
            unicode = Rex::Text.to_unicode('')

            encoded = ''
            encoded << [
              unicode.length,
              unicode.length,
              0x20020
            ].pack('vvV')
            encoded
          end

          # Encodes the logon_server info (constant)
          #
          # @return [String]
          def encode_logon_server_info
            unicode = Rex::Text.to_unicode('')
            encoded = ''
            encoded << [
              ''.length,
              ''.length
            ].pack('Q<V')
            encoded << unicode

            encoded
          end

          # Encodes the logon_domain_name id
          #
          # @return [String]
          def encode_logon_domain_name
            unicode = Rex::Text.to_unicode(logon_domain_name)

            encoded = ''
            encoded << [
              unicode.length,
              unicode.length,
              0x20024
            ].pack('vvV')

            encoded
          end

          # Encodes the logon_domain_name info field
          #
          # @return [String]
          def encode_logon_domain_name_info
            unicode = Rex::Text.to_unicode(logon_domain_name)
            encoded = ''
            encoded << [
              logon_domain_name.length,
              logon_domain_name.length
            ].pack('Q<V')
            encoded << unicode

            encoded
          end

          # Encodes the logon_domain_id id
          #
          # @return [String]
          def encode_logon_domain_id
            encoded = ''
            encoded << [0x20028].pack('V')

            encoded
          end

          # Encodes the logon_domain_id info field
          #
          # @return [String]
          def encode_logon_domain_id_info
            components = logon_domain_id.split('-')
            unless components[0] == 'S'
              raise ::RuntimeError, 'PAC-LOGON-INFO encoding failed: incorrect LogonDomainId'
            end
            components.slice!(0) # Delete the 'S' component

            encoded = ''
            encoded << [
                components.length - 2,
                components[0].to_i,
                components.length - 2
            ].pack('VCC')

            encoded << [
                components[1].to_i >> 16,
                components[1].to_i & 0xffff
            ].pack('Nn')

            components[2, components.length].each do |c|
              encoded << [c.to_i].pack('V')
            end

            encoded
          end

          # Encodes the reserved_one (constant)
          #
          # @return [String]
          def encode_reserved_one
            [0, 0].pack('VV')
          end

          # Encodes the user_account_control (constant)
          #
          # @return [String]
          def encode_user_account_control
            [USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD].pack('V')
          end

          # Encodes the reserved_three (constant)
          #
          # @return [String]
          def encode_reserved_three
            [0, 0, 0, 0, 0, 0, 0].pack('V*')
          end

          # Encodes the sid_count (constant)
          #
          # @return [String]
          def encode_sid_count
            [0].pack('V')
          end

          # Encodes the extra_sids (constant)
          #
          # @return [String]
          def encode_extra_sids
            [0].pack('V')
          end

          # Encodes the resource_group_domain_sid (constant)
          #
          # @return [String]
          def encode_resource_group_domain_sid
            [0].pack('V')
          end

          # Encodes the resource_group_count (constant)
          #
          # @return [String]
          def encode_resource_group_count
            [0].pack('V')
          end

          # Encodes the resource_group_ids (constant)
          #
          # @return [String]
          def encode_resource_group_ids
            [0].pack('V')
          end
        end
      end
    end
  end
end