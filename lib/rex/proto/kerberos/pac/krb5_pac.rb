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

    ndr_uint8  :version, initial_value: 1
    ndr_uint8  :endianness, initial_value: 0x10
    ndr_uint16 :common_header_length, initial_value: 8
    ndr_uint32 :filler, asserted_value: 0xCCCCCCCC
  end

  # [2.2.6.2 Private Header for Constructed Type](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/63949ba8-bc88-4c0c-9377-23f14b197827)
  class TypeSerialization1PrivateHeader < NdrStruct
    default_parameter byte_align: 8
    endian :little

    ndr_uint32 :object_buffer_length
    ndr_uint32 :filler, asserted_value: 0x00000000
  end

  # [2.2.6 Type Serialization Version 1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/9a1d0f97-eac0-49ab-a197-f1a581c2d6a0)
  class TypeSerialization1 < NdrStruct
    default_parameter byte_align: 4
    endian :little
    search_prefix :type_serialization1

    common_type_header  :common_header
    private_header      :private_header
  end
end

# full MIDL spec for PAC
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/1d4912dd-5115-4124-94b6-fa414add575f
module Rex::Proto::Kerberos::Pac

  # https://github.com/rapid7/metasploit-framework/blob/b2eb348d943af25adfc41e6fa689d9da00154685/lib/rex/proto/kerberos/crypto.rb#L37-L42
  # I don't know what the rest of these should be, the doc only mentions the three below
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6e95edd3-af93-41d4-8303-6c7955297315
  CHECKSUM_SIGNATURE_LENGTH = {
    Rex::Proto::Kerberos::Crypto::Checksum::RSA_MD5 => 16, # TODO check and remove
    # Rex::Proto::Kerberos::Crypto::Checksum::MD5_DES => 0, # ??? dunno
    # Rex::Proto::Kerberos::Crypto::Checksum::SHA1_DES3 => 0, # ??? dunno
    Rex::Proto::Kerberos::Crypto::Checksum::SHA1_AES128 => 12,
    Rex::Proto::Kerberos::Crypto::Checksum::SHA1_AES256 => 12,
    Rex::Proto::Kerberos::Crypto::Checksum::HMAC_MD5 => 16
  }.freeze

  # rpc_unicode_string1
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/94a16bb6-c610-4cb9-8db6-26f15f560061
  class RpcUnicodeString1 < BinData::Record # Remove once struct in ruby smb is fixed
    endian :little

    uint16 :string_length
    uint16 :maximum_length
    uint32 :wchar_buffer_pointer # ruby_smb/dcerpc/ndr.rb
  end

  class RpcUnicodeStringInfo < BinData::Record
    endian :little

    uint64 :string_length
    uint32 :maximum_length

    string16 :unicode_string, length: -> { maximum_length * 2 } # uses WCHAR, i.e. 2bytes per char
  end

  # class RpcSidIdentifierAuthority < BinData::Record
  #   endian :little
  #
  #   array :identifier_authority, type: :uint8, initial_length: 6
  # end

  # class RpcSid < BinData::Record
  #   endian :little
  #
  #   uint8 :revision
  #   uint8 :sub_authority_count
  #   rpc_sid_identifier_authority :rpc_sid_identifier_authority
  #   array :sub_authority, type: :uint32, initial_length: :sub_authority_count
  # end

  class GroupMemberships < BinData::Record
    endian :little

    uint32 :number_of_memberships
    array :group_memberships, type: :group_membership, initial_length: :number_of_memberships
  end

  class UserSessionKey < BinData::Record
    endian :little

    uint128 :session_key
  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/e465cb27-4bc1-4173-8be0-b5fd64dc9ff7
  class Krb5ClientInfo < BinData::Record
    endian :little

    file_time :client_id
    uint16 :name_length
    string16 :name, length: :name_length
  end

  class Krb5PacSignatureData < BinData::Record
    endian :little

    uint32 :signature_type
    array :signature, type: :uint8, initial_length: -> { CHECKSUM_SIGNATURE_LENGTH.fetch(signature_type) }
  end

  class Krb5PacInfoBuffer < BinData::Record
    endian :little

    uint32 :ul_type
    uint32 :cb_buffer_size
    uint64 :offset
  end

  class Krb5PacType < BinData::Record
    endian :little

    uint32 :c_buffers
    uint32 :version, asserted_value: 0x00000000

    array :pac_info_buffer, type: :krb5_pac_info_buffer, initial_length: :c_buffers

  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73
  class Krb5LogonInfo < BinData::Record
    endian :little

    file_time :logon_time
    file_time :logoff_time
    file_time :kick_off_time
    file_time :password_last_set
    file_time :password_can_change
    file_time :password_must_change

    rpc_unicode_string1 :effective_name
    rpc_unicode_string1 :full_name
    rpc_unicode_string1 :logon_script
    rpc_unicode_string1 :profile_path
    rpc_unicode_string1 :home_directory
    rpc_unicode_string1 :home_directory_drive

    uint16 :logon_count
    uint16 :bad_password_count
    uint32 :user_id
    uint32 :primary_group_id
    uint32 :group_count
    uint32 :group_ids_ptr
    uint32 :user_flags

    user_session_key :user_session_key

    rpc_unicode_string1 :logon_server
    rpc_unicode_string1 :logon_domain_name

    uint32 :logon_domain_id_ptr #prpc_sid :logon_domain_id_ptr
    uint64 :reserved_1
    uint32 :user_account_control
    uint32 :sub_auth_status

    file_time :last_successful_i_logon
    file_time :last_failed_i_logon

    uint32 :failed_i_logon_count
    uint32 :reserved_3
    uint32 :sid_count
    uint32 :extra_sids_ptr
    uint32 :resource_group_domain_sid_ptr #prpc_sid :resource_group_domain_sid_ptr
    uint32 :resource_group_count
    uint32 :resource_group_ids_ptr
  end

  class Krb5ValidationInfo < BinData::Record
    endian :little
    default_parameter byte_align: 4

    type_serialization1_common_type_header :common_type_header

    type_serialization1_private_header :private_header_constructed_type

    # I don't know where this comes from but the og impl has it???
    # The next 4 bytes, from 0x0000006E through 0x00000071, are an RPC unique pointer referent, as defined in [C706] section 14.3.10.
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/7d4f403e-cc0a-455f-8eeb-f38326a903a9
    # https://github.com/rapid7/metasploit-framework/blob/5f85175f56e3bf993458ebd95c7d03ba30364198/lib/rex/proto/kerberos/pac/logon_info.rb#L100-L102
    uint32 :element_id, asserted_value: 0x20000

    krb5_logon_info :logon_info

    rpc_unicode_string_info :effective_name_info
    rpc_unicode_string_info :full_name_info
    rpc_unicode_string_info :logon_script_info
    rpc_unicode_string_info :profile_path_info
    rpc_unicode_string_info :home_directory_info
    rpc_unicode_string_info :home_directory_drive_info

    group_memberships :group_ids_info

    rpc_unicode_string_info :logon_server_info
    rpc_unicode_string_info :logon_domain_name_info
    rpc_sid :logon_domain_id_info #https://github.com/rapid7/ruby_smb/blob/95ffce90f3fbd2b2d8d00b643e318fc38cce52bd/lib/ruby_smb/dcerpc/samr/rpc_sid.rb

    group_memberships :resource_group_ids, onlyif: -> { logon_info.resource_group_count > 0 }

    # I think extra sids go here but I don't know what that looks like and we don't have an example atm
    # PKERB_SID_AND_ATTRIBUTES
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/311aab27-ebdf-47f7-b939-13dc99b15341
  end

  class Krb5Pac < BinData::Record
    endian :little
    # default_parameter byte_align: 8# does not work, dunno why

    krb5_pac_type :pac_type
    # This order doesn't seem set in stone also there can be more/fewer fields
    krb5_validation_info :logon_info, byte_align: 8
    krb5_client_info :client_info, byte_align: 8
    krb5_pac_signature_data :server_checksum, byte_align: 8
    krb5_pac_signature_data :private_server_checksum, byte_align: 8
  end
end

