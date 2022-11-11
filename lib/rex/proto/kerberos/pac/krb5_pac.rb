# frozen_string_literal: true

require 'bindata'
require 'ruby_smb/dcerpc'

# Temp borrowed from christophe
# https://github.com/cdelafuente-r7/metasploit-framework/blob/70767de71824557d4f8ad14831ed0121789d4363/lib/rex/proto/kerberos/pac/credential_info.rb#L3
module RubySMB::Dcerpc::Ndr
  # [2.2.6.1 Common Type Header for the Serialization Stream](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/6d75d40e-e2d2-4420-b9e9-8508a726a9ae)
  class TypeSerialization1CommonTypeHeader < NdrStruct
    default_parameter byte_align: 8
    endian :little

    ndr_uint8 :version, asserted_value: 1
    ndr_uint8 :endianness, asserted_value: 0x10
    ndr_uint16 :common_header_length, asserted_value: 8
    ndr_uint32 :filler, asserted_value: 0xCCCCCCCC
  end

  # [2.2.6.2 Private Header for Constructed Type](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/63949ba8-bc88-4c0c-9377-23f14b197827)
  class TypeSerialization1PrivateHeader < NdrStruct
    default_parameter byte_align: 8
    mandatory_parameter :buffer_length
    endian :little

    ndr_uint32 :object_buffer_length, initial_value: :buffer_length
    ndr_uint32 :filler, asserted_value: 0x00000000
  end
end

# full MIDL spec for PAC
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/1d4912dd-5115-4124-94b6-fa414add575f
module Rex::Proto::Kerberos::Pac
  # https://github.com/rapid7/metasploit-framework/blob/b2eb348d943af25adfc41e6fa689d9da00154685/lib/rex/proto/kerberos/crypto.rb#L37-L42
  # I don't know what the rest of these should be, the doc only mentions the three below
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6e95edd3-af93-41d4-8303-6c7955297315
  CHECKSUM_SIGNATURE_LENGTH = {
    Rex::Proto::Kerberos::Crypto::Checksum::RSA_MD5 => 16, # TODO: check and remove
    # Rex::Proto::Kerberos::Crypto::Checksum::MD5_DES => 0, # ??? dunno
    # Rex::Proto::Kerberos::Crypto::Checksum::SHA1_DES3 => 0, # ??? dunno
    Rex::Proto::Kerberos::Crypto::Checksum::SHA1_AES128 => 12,
    Rex::Proto::Kerberos::Crypto::Checksum::SHA1_AES256 => 12,
    Rex::Proto::Kerberos::Crypto::Checksum::HMAC_MD5 => 16
  }.freeze

  # rpc_unicode_string_ptr
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/94a16bb6-c610-4cb9-8db6-26f15f560061
  # Remove once struct in ruby smb is fixed
  class RpcUnicodeStringPtr < BinData::Record
    mandatory_parameter :ptr

    endian :little

    uint16 :string_length
    uint16 :maximum_length
    uint32 :wchar_buffer_pointer, value: :ptr # ruby_smb/dcerpc/ndr.rb

    def assign(val)
      case val
      when :null
        self.buffer_length = 0
        self.maximum_length = 0
      when BinData::Stringz, BinData::String, String
        val_length = val.strip.length
        self.string_length = val_length * 2
        self.maximum_length = val_length * 2
      else
        super
      end
    end
  end

  class RpcUnicodeStringInfo < BinData::Record
    endian :little

    uint64 :string_length
    uint32 :maximum_length

    string16 :unicode_string, read_length: -> { maximum_length * 2 } # uses WCHAR, i.e. 2bytes per char

    def assign(val)
      case val
      when :null
        self.buffer = val
        self.buffer_length = 0
        self.maximum_length = 0
      when BinData::Stringz, BinData::String, String
        self.unicode_string = val.to_s
        val_length = val.strip.length
        self.string_length = val_length
        self.maximum_length = val_length
      else
        super
      end
    end
  end

  class GroupMembership < BinData::Record
    endian :little

    uint32 :relative_id
    uint32 :attributes
  end

  class GroupMemberships < BinData::Record
    endian :little

    uint32 :number_of_memberships
    array :group_memberships, type: :group_membership, initial_length: :number_of_memberships

    def assign(val)
      case val
      when GroupMemberships
        super
      when Array
        self.number_of_memberships = val.length
        val.each_with_index do |id, index|
          group_memberships[index].assign(relative_id: id, attributes: SE_GROUP_ALL)
        end
      end
    end

  end

  class UserSessionKey < BinData::Record
    endian :little

    # @!attribute [rw] session_key
    #   @return [Integer]
    uint128 :session_key
  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/e465cb27-4bc1-4173-8be0-b5fd64dc9ff7
  class Krb5ClientInfo < BinData::Record
    endian :little
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: 0x0A

    # @!attribute [rw] client_id
    #   @return [FileTime] Kerberos initial ticket-granting ticket (TGT) authentication time
    file_time :client_id

    # @!attribute [rw] name_length
    #   @return [Integer]
    uint16 :name_length, initial_value: -> { name.num_bytes }

    # @!attribute [rw] read_length
    #   @return [String]
    string16 :name, read_length: :name_length
  end

  class Krb5PacSignatureData < BinData::Record
    endian :little

    # @!attribute [rw] signature_type
    #   @return [Integer] Defines the cryptographic system used to calculate the checksum
    # @see Rex::Proto::Kerberos::Crypto::Checksum
    uint32 :signature_type

    # @!attribute [rw] signature
    #   @return [String]
    string :signature, length: -> { CHECKSUM_SIGNATURE_LENGTH.fetch(signature_type) }

  end

  class Krb5PacServerChecksum < Krb5PacSignatureData
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: 0x06
  end

  class Krb5PacPrivServerChecksum < Krb5PacSignatureData
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: 0x07
  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73
  class Krb5ValidationInfo < BinData::Record
    endian :little
    default_parameter byte_align: 4

    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: 0x01

    # @!attribute [rw] common_type_header
    #   @return [TypeSerialization1CommonTypeHeader]
    type_serialization1_common_type_header :common_type_header

    # @!attribute [rw] private_header_constructed_type
    #   @return [TypeSerialization1PrivateHeader]
    type_serialization1_private_header :private_header_constructed_type, buffer_length: -> { num_bytes - element_id.rel_offset } # number of bytes left in this object

    # I don't know where this comes from but the og impl has it???
    # The next 4 bytes, from 0x0000006E through 0x00000071, are an RPC unique pointer referent, as defined in [C706] section 14.3.10.
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/7d4f403e-cc0a-455f-8eeb-f38326a903a9
    # https://github.com/rapid7/metasploit-framework/blob/5f85175f56e3bf993458ebd95c7d03ba30364198/lib/rex/proto/kerberos/pac/logon_info.rb#L100-L102

    # @!attribute [r] element_id
    #   @return [Integer]
    uint32 :element_id, asserted_value: NETLOGON_FLAG

    # @!attribute [rw] logon_time
    #   @return [FileTime] User account's lastLogon attribute
    file_time :logon_time

    # @!attribute [rw] logoff_time
    #   @return [FileTime] Time the client's logon session is set to expire
    file_time :logoff_time, initial_value: NEVER_EXPIRE

    # @!attribute [rw] kick_off_time
    #   @return [FileTime] logoff_time minus the user account's forceLogoff attribute
    file_time :kick_off_time, initial_value: NEVER_EXPIRE

    # @!attribute [rw] password_last_set
    #   @return [FileTime] User account's pwdLastSet attribute
    file_time :password_last_set

    # @!attribute [rw] password_can_change
    #   @return [FileTime] Time at which the client's password is allowed to change
    file_time :password_can_change

    # @!attribute [rw] password_must_change
    #   @return [FileTime] Time at which the client's password expires
    file_time :password_must_change, initial_value: NEVER_EXPIRE

    # @!attribute [rw] effective_name_ptr
    #   @return [RpcUnicodeStringPtr] Pointer to user account's samAccountName attribute
    rpc_unicode_string_ptr :effective_name_ptr, ptr: 0x20004

    # @!attribute [rw] full_name_ptr
    #   @return [RpcUnicodeStringPtr] Pointer to user account's full name for interactive logon
    rpc_unicode_string_ptr :full_name_ptr, ptr: 0x20008

    # @!attribute [rw] logon_script_ptr
    #   @return [RpcUnicodeStringPtr] Pointer to user account's scriptPath attribute
    rpc_unicode_string_ptr :logon_script_ptr, ptr: 0x2000C

    # @!attribute [rw] profile_path_ptr
    #   @return [RpcUnicodeStringPtr] Pointer to user account's profilePath attribute
    rpc_unicode_string_ptr :profile_path_ptr, ptr: 0x20010

    # @!attribute [rw] home_directory_ptr
    #   @return [RpcUnicodeStringPtr] Pointer to user account's HomeDirectory attribute
    rpc_unicode_string_ptr :home_directory_ptr, ptr: 0x20014

    # @!attribute [rw] home_directory_drive_ptr
    #   @return [RpcUnicodeStringPtr] Pointer to user account's HomeDrive attribute
    rpc_unicode_string_ptr :home_directory_drive_ptr, ptr: 0x20018

    # @!attribute [rw] logon_count
    #   @return [Integer] User account's LogonCount attribute
    uint16 :logon_count

    # @!attribute [rw] bad_password_count
    #   @return [Integer] User account's badPwdCount attribute
    uint16 :bad_password_count

    # @!attribute [rw] user_id
    #   @return [Integer] RID of the account
    uint32 :user_id

    # @!attribute [rw] primary_group_id
    #   @return [Integer] RID for the primary group to which this account belongs
    uint32 :primary_group_id

    # @!attribute [rw] group_count
    #   @return [Integer] Number of groups within the account domain to which the account belongs
    uint32 :group_count, initial_value: -> { group_ids_info.number_of_memberships }

    # @!attribute [rw] group_ids_ptr
    #   @return [Integer] A pointer to a list of GROUP_MEMBERSHIP structures that contains the groups to which the account belongs in the account domain
    uint32 :group_ids_ptr, initial_value: 0x2001c

    # @!attribute [rw] user_flags
    #   @return [Integer] A set of bit flags that describe the user's logon information
    uint32 :user_flags

    # @!attribute [rw] user_session_key
    #   @return [Integer] A session key that is used for cryptographic operations on a session
    user_session_key :user_session_key

    # @!attribute [rw] logon_server_ptr
    #   @return [RpcUnicodeStringPtr] Pointer to NetBIOS name of the Kerberos KDC that performed the authentication server (AS) ticket request
    rpc_unicode_string_ptr :logon_server_ptr, string: :logon_server, ptr: 0x20020

    # @!attribute [rw] logon_domain_name_ptr
    #   @return [RpcUnicodeStringPtr] Pointer to NetBIOS name of the domain to which this account belongs
    rpc_unicode_string_ptr :logon_domain_name_ptr, string: :logon_domain_name, ptr: 0x20024

    # @!attribute [rw] logon_domain_id_ptr
    #   @return [Integer] Pointer to SID for the domain specified in LogonDomainName
    uint32 :logon_domain_id_ptr, initial_value: 0x20028 # prpc_sid :logon_domain_id_ptr

    # @!attribute [rw] reserved_1
    #   @return [Integer] This member is reserved
    uint64 :reserved_1

    # @!attribute [rw] user_account_control
    #   @return [Integer] Set of bit flags that represent information about this account
    uint32 :user_account_control, initial_value: USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD

    # @!attribute [rw] sub_auth_status
    #   @return [Integer] Subauthentication package's status code
    uint32 :sub_auth_status

    # @!attribute [rw] last_successful_i_logon
    #   @return [FileTime] User account's msDS-LastSuccessfulInteractiveLogonTime
    file_time :last_successful_i_logon

    # @!attribute [rw] last_failed_i_logon
    #   @return [FileTime] User account's msDS-LastFailedInteractiveLogonTime
    file_time :last_failed_i_logon

    # @!attribute [rw] failed_i_logon_count
    #   @return [Integer] User account's msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon
    uint32 :failed_i_logon_count

    # @!attribute [rw] reserved_3
    #   @return [Integer] This member is reserved
    uint32 :reserved_3

    # @!attribute [rw] sid_count
    #   @return [Integer] Total number of SIDs present in the ExtraSids member
    uint32 :sid_count

    # @!attribute [rw] extra_sids_ptr
    #   @return [Integer] A pointer to a list of KERB_SID_AND_ATTRIBUTES structures that contain a list of SIDs
    #   corresponding to groups in domains other than the account domain to which the principal belongs
    uint32 :extra_sids_ptr

    # @!attribute [rw] resource_group_domain_sid_ptr
    #   @return [Integer] Pointer to SID of the domain for the server whose resources the client is authenticating to
    uint32 :resource_group_domain_sid_ptr # prpc_sid :resource_group_domain_sid_ptr

    # @!attribute [rw] resource_group_count
    #   @return [Integer] Number of resource group identifiers stored in ResourceGroupIds
    uint32 :resource_group_count

    # @!attribute [rw] resource_group_ids_ptr
    #   @return [Integer] Pointer to list of GROUP_MEMBERSHIP structures that contain the RIDs and attributes of the
    #   account's groups in the resource domain
    uint32 :resource_group_ids_ptr

    # @!attribute [rw] effective_name_info
    #   @return [RpcUnicodeStringInfo] User account's samAccountName attribute
    rpc_unicode_string_info :effective_name_info

    # @!attribute [rw] full_name_info
    #   @return [RpcUnicodeStringInfo] User account's full name for interactive logon
    rpc_unicode_string_info :full_name_info

    # @!attribute [rw] logon_script_info
    #   @return [RpcUnicodeStringInfo] User account's scriptPath attribute
    rpc_unicode_string_info :logon_script_info

    # @!attribute [rw] profile_path_info
    #   @return [RpcUnicodeStringInfo] User account's profilePath attribute
    rpc_unicode_string_info :profile_path_info

    # @!attribute [rw] home_directory_info
    #   @return [RpcUnicodeStringInfo] User account's HomeDirectory attribute
    rpc_unicode_string_info :home_directory_info

    # @!attribute [rw] home_directory_drive_info
    #   @return [RpcUnicodeStringInfo] User account's HomeDrive attribute
    rpc_unicode_string_info :home_directory_drive_info

    # @!attribute [rw] group_ids_info
    #   @return [GroupMemberships]
    group_memberships :group_ids_info

    # @!attribute [rw] logon_server_info
    #   @return [RpcUnicodeStringInfo] NetBIOS name of the Kerberos KDC that performed the authentication server (AS) ticket request
    rpc_unicode_string_info :logon_server_info

    # @!attribute [rw] logon_domain_name_info
    #   @return [RpcUnicodeStringInfo] NetBIOS name of the domain to which this account belongs
    rpc_unicode_string_info :logon_domain_name_info

    # https://github.com/rapid7/ruby_smb/blob/95ffce90f3fbd2b2d8d00b643e318fc38cce52bd/lib/ruby_smb/dcerpc/samr/rpc_sid.rb
    # @!attribute [rw] logon_domain_id
    #   @return [RpcSid] SID for the domain specified in LogonDomainName
    rpc_sid :logon_domain_id

    # @!attribute [rw] resource_group_ids
    #   @return [GroupMemberships] List of GROUP_MEMBERSHIP structures that contain the RIDs and attributes of the account's groups in the resource domain
    group_memberships :resource_group_ids, onlyif: -> { resource_group_count > 0 }

    # I think extra sids go here but I don't know what that looks like and we don't have an example atm
    # PKERB_SID_AND_ATTRIBUTES
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/311aab27-ebdf-47f7-b939-13dc99b15341
    def assign(val)
      case val
      when Hash
        new_val = val.merge({
          effective_name_ptr: val.fetch(:effective_name, ''),
          effective_name_info: val.fetch(:effective_name, ''),

          full_name_ptr: val.fetch(:full_name, ''),
          full_name_info: val.fetch(:full_name, ''),

          logon_script_ptr: val.fetch(:logon_script, ''),
          logon_script_info: val.fetch(:logon_script, ''),

          profile_path_ptr: val.fetch(:profile_path, ''),
          profile_path_info: val.fetch(:profile_path, ''),

          home_directory_ptr: val.fetch(:home_directory, ''),
          home_directory_info: val.fetch(:home_directory, ''),

          home_directory_drive_ptr: val.fetch(:home_directory_drive, ''),
          home_directory_drive_info: val.fetch(:home_directory_drive, ''),

          logon_server_ptr: val.fetch(:logon_server, ''),
          logon_server_info: val.fetch(:logon_server, ''),

          logon_domain_name_ptr: val.fetch(:logon_domain_name, ''),
          logon_domain_name_info: val.fetch(:logon_domain_name, ''),

          group_ids_info: val.fetch(:group_ids, [])
        })
        super(new_val)
      else
        super
      end
    end

    def effective_name=(val)
      effective_name_ptr.assign val
      effective_name_info.assign val
    end

    def effective_name()
      effective_name_info.unicode_string
    end

    def logon_domain_name=(val)
      logon_domain_name_ptr.assign val
      logon_domain_name_info.assign val
    end
    def group_ids=(val)
      group_ids_info.assign val
    end
  end

  class Krb5PacElement < BinData::Choice
    krb5_validation_info 0x00000001
    krb5_client_info 0x0000000A
    krb5_pac_server_checksum 0x00000006
    krb5_pac_priv_server_checksum 0x00000007
  end

  class Krb5PacInfoBuffer < BinData::Record
    endian :little

    # @!attribute [rw] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    uint32 :ul_type

    # @!attribute [rw] cb_buffer_size
    #   @return [Integer]
    uint32 :cb_buffer_size, initial_value: -> { buffer.pac_element.num_bytes }

    # @!attribute [rw] offset
    #   @return [Integer]
    uint64 :offset

    delayed_io :buffer, read_abs_offset: :offset do
      # @!attribute [rw] pac_element
      #   @return [Krb5PacElement]
      krb5_pac_element :pac_element, selection: -> { ul_type }
      string :padding, length: -> { bytes_to_align(pac_element.num_bytes) }
    end
  end



  class Krb5Pac < BinData::Record
    endian :little
    auto_call_delayed_io

    # @!attribute [rw] c_buffers
    #   @return [Integer]
    uint32 :c_buffers, asserted_value: -> { pac_info_buffers.length }

    # @!attribute [r] version
    #   @return [Integer]
    uint32 :version, asserted_value: 0x00000000

    # @!attribute [rw] pac_info_buffers
    #   @return [Array<Krb5PacInfoBuffer>]
    array :pac_info_buffers, type: :krb5_pac_info_buffer, initial_length: :c_buffers

    def assign(val)
      case val
      when Hash
        pac_infos = val[:pac_elements].map do |pac_element|
          { ul_type: pac_element.ul_type, buffer: { pac_element: pac_element } }
        end
        new_val = val.merge(pac_info_buffers: pac_infos)
        super(new_val)
      else
        super
      end
    end

    # Calculates the checksums, can only be done after all other fields are set
    def calculate_checksums(key: nil)
      server_checksum = nil
      priv_server_checksum = nil
      pac_info_buffers.each do |info_buffer|
        pac_element = info_buffer.buffer.pac_element
        if pac_element.ul_type == 6
          server_checksum = pac_element
        elsif pac_element.ul_type == 7
          priv_server_checksum = pac_element
        end
      end
      server_checksum.signature = calculate_checksum(server_checksum.signature_type, key, to_binary_s)

      priv_server_checksum.signature = calculate_checksum(priv_server_checksum.signature_type, key, server_checksum.signature)
    end

    # Calculates the offsets for pac_elements if they haven't yet been set
    def calculate_offsets
      offset = pac_info_buffers.abs_offset + pac_info_buffers.num_bytes
      pac_info_buffers.each do |pac_info|
        next unless pac_info.offset == 0
        pac_info.offset = offset
        offset += pac_info.cb_buffer_size
        offset += bytes_to_align(offset)
      end
    end

    # Call this when you are done setting fields in the object
    # in order to finalise the data
    def finish
      calculate_offsets
      calculate_checksums
    end
    def bytes_to_align(n, align: 8)
      (align - (n % align)) % align
    end


    private

    def calculate_checksum(signature_type, key, data)
      checksummer = Rex::Proto::Kerberos::Crypto::Checksum.from_checksum_type(signature_type)
      checksummer.checksum(key, Rex::Proto::Kerberos::Crypto::KeyUsage::KERB_NON_KERB_CKSUM_SALT, data)
    end
  end
end
