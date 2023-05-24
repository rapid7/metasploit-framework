# frozen_string_literal: true

require 'bindata'
require 'ruby_smb/dcerpc'
require 'rex/proto/ms_dtyp'

# full MIDL spec for PAC
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/1d4912dd-5115-4124-94b6-fa414add575f
module Rex::Proto::Kerberos::Pac
  # https://github.com/rapid7/metasploit-framework/blob/b2eb348d943af25adfc41e6fa689d9da00154685/lib/rex/proto/kerberos/crypto.rb#L37-L42
  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/6e95edd3-af93-41d4-8303-6c7955297315
  CHECKSUM_SIGNATURE_LENGTH = {
    # Used by: modules/auxiliary/admin/kerberos/ms14_068_kerberos_checksum.rb.
    # Not defined in the specification explicitly, but the exploit uses a weaker checksum to bypass Microsoft's PAC security methods
    Rex::Proto::Kerberos::Crypto::Checksum::RSA_MD5 => 16,
    Rex::Proto::Kerberos::Crypto::Checksum::SHA1_AES128 => 12,
    Rex::Proto::Kerberos::Crypto::Checksum::SHA1_AES256 => 12,
    Rex::Proto::Kerberos::Crypto::Checksum::HMAC_MD5 => 16,
    0xffffff76 => 16 # Negative 138 two's complement (HMAC_MD5)
  }.freeze

  class CypherBlock < RubySMB::Dcerpc::Ndr::NdrStruct
    default_parameter byte_align: 1
    ndr_fixed_byte_array :data, initial_length: 8
  end

  class UserSessionKey < RubySMB::Dcerpc::Ndr::NdrStruct
    default_parameter byte_align: 1
    endian :little

    # @!attribute [rw] session_key
    #   @return [Integer]
    ndr_fix_array :session_key, initial_length: 2, type: :cypher_block
  end

  class Krb5SidAndAttributes < RubySMB::Dcerpc::Ndr::NdrStruct
    default_parameters byte_align: 4
    prpc_sid :sid
    ndr_uint32 :attributes
  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/311aab27-ebdf-47f7-b939-13dc99b15341
  #
  # [SIDATT] https://learn.microsoft.com/en-gb/windows/win32/api/winnt/ns-winnt-token_groups?redirectedfrom=MSDN
  class GroupAttributes < BinData::Record
    endian :big

    2.times do
      bit1 :"_reserved_#{self.fields.length}"
    end

    # @!attribute [rw] resource
    #   @return [BinData::Bit1] This setting means that the group is a domain-local or resource group. Corresponds to SE_GROUP_RESOURCE. For more information, see [SIDATT].
    bit1 :resource

    25.times do
      bit1 :"_reserved_#{self.fields.length}"
    end

    # @!attribute [rw] owner
    #   @return [BinData::Bit1] This setting means that the group can be assigned as an owner of a resource. Corresponds to SE_GROUP_OWNER. For more information, see [SIDATT].
    bit1 :owner

    # @!attribute [rw] enabled
    #   @return [BinData::Bit1] This setting means that the group is enabled for use. Corresponds to SE_GROUP_ENABLED. For more information, see [SIDATT].
    bit1 :enabled

    # @!attribute [rw] enabled_by_default
    #   @return [BinData::Bit1] This setting means that the group is marked as enabled by default. Corresponds to SE_GROUP_ENABLED_BY_DEFAULT. For more information, see [SIDATT].
    bit1 :enabled_by_default

    # @!attribute [rw] mandatory
    #   @return [BinData::Bit1] This setting means that the group is mandatory for the user and cannot be disabled. Corresponds to SE_GROUP_MANDATORY. For more information, see [SIDATT].
    bit1 :mandatory
  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73
  class UserFlagAttributes < BinData::Record
    endian :big

    18.times do
      bit1 :"_reserved_#{self.fields.length}"
    end

    # @!attribute [rw] used_lmv2_auth_and_ntlmv2_session_key
    #   @return [BinData::Bit1] The LMv2 response from the LmChallengeResponseFields ([MS-NLMP] section 2.2.1.3) was used for authentication and the NTLMv2 response from the NtChallengeResponseFields ([MS-NLMP] section 2.2.1.3) was used session key generation.
    bit1 :used_lmv2_auth_and_ntlmv2_session_key

    # @!attribute [rw] used_lmv2_auth_and_session_key
    #   @return [BinData::Bit1] The LMv2 response from the LmChallengeResponseFields ([MS-NLMP] section 2.2.1.3) was used for authentication and session key generation.
    bit1 :used_lmv2_auth_and_session_key

    # @!attribute [rw] used_ntlmv2_auth_and_session_key
    #   @return [BinData::Bit1] The NTLMv2 response from the NtChallengeResponseFields ([MS-NLMP] section 2.2.1.3) was used for authentication and session key generation.
    bit1 :used_ntlmv2_auth_and_session_key

    # @!attribute [rw] profile_path_populated
    #   @return [BinData::Bit1] Indicates that ProfilePath is populated.
    bit1 :profile_path_populated

    # @!attribute [rw] resource_group_ids
    #   @return [BinData::Bit1] Indicates that the ResourceGroupIds field is populated.
    bit1 :resource_group_ids

    # @!attribute [rw] accepts_ntlmv2
    #   @return [BinData::Bit1] Indicates that the domain controller understands NTLMv2.
    bit1 :accepts_ntlmv2

    # @!attribute [rw] machine_account
    #   @return [BinData::Bit1] Indicates that the account is a machine account.
    bit1 :machine_account

    # @!attribute [rw] sub_authentication
    #   @return [BinData::Bit1] Sub-authentication used; session key came from the sub-authentication package.
    bit1 :sub_authentication

    # @!attribute [rw] extra_sids
    #   @return [BinData::Bit1] Indicates that the ExtraSids field is populated and contains additional SIDs.
    bit1 :extra_sids

    1.times do
      bit1 :"_reserved_#{self.fields.length}"
    end

    # @!attribute [rw] lan_manager
    #   @return [BinData::Bit1] LAN Manager key was used for authentication.
    bit1 :lan_manager

    1.times do
      bit1 :"_reserved_#{self.fields.length}"
    end

    # @!attribute [rw] no_encryption
    #   @return [BinData::Bit1] No encryption is available.
    bit1 :no_encryption

    # @!attribute [rw] guest
    #   @return [BinData::Bit1] Authentication was done via the GUEST account; no password was used
    bit1 :guest
  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec
  #
  # [RFC4120] https://www.rfc-editor.org/rfc/rfc4120
  # [RFC3961] https://www.ietf.org/rfc/rfc3961.txt
  # [MS-KILE] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9
  # [MS-LSAD] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc
  class UserAccountAttributes < BinData::Record
    endian :big

    10.times do
      bit1 :"_reserved_#{self.fields.length}"
    end

    # @!attribute [rw] use_aes_keys
    #   @return [BinData::Bit1] This bit is ignored by clients and servers.
    bit1 :use_aes_keys

    # @!attribute [rw] partial_secrets_account
    #   @return [BinData::Bit1] Specifies that the object is a read-only domain controller (RODC).
    bit1 :partial_secrets_account

    # @!attribute [rw] no_auth_data_required
    #   @return [BinData::Bit1] This bit is used by the Kerberos protocol. It indicates that when the key distribution center (KDC) is issuing a service ticket for this account, the privilege attribute certificate (PAC) is not to be included. For more information, see [RFC4120].
    bit1 :no_auth_data_required

    # @!attribute [rw] trusted_to_authenticate_for_delegation
    #   @return [BinData::Bit1] This bit is used by the Kerberos protocol, as specified in [MS-KILE] section 3.3.1.1.
    bit1 :trusted_to_authenticate_for_delegation

    # @!attribute [rw] password_expired
    #   @return [BinData::Bit1] Specifies that the password age on the user has exceeded the maximum password age policy.
    bit1 :password_expired

    # @!attribute [rw] dont_require_preauth
    #   @return [BinData::Bit1] This bit is used by the Kerberos protocol. It indicates that the account is not required to present valid preauthentication data, as described in [RFC4120] section 7.5.2.
    bit1 :dont_require_preauth

    # @!attribute [rw] use_des_key_only
    #   @return [BinData::Bit1] This bit is used by the Kerberos protocol. It indicates that only des-cbc-md5 or des-cbc-crc keys (as defined in [RFC3961]) are used in the Kerberos protocol for this account.
    bit1 :use_des_key_only

    # @!attribute [rw] not_delegated
    #   @return [BinData::Bit1] This bit is used by the Kerberos protocol. It indicates that the ticket-granting tickets (TGTs) of this account and the service tickets obtained by this account are not marked as forwardable or proxiable when the forwardable or proxiable ticket flags are requestedFor more information, see [RFC4120].
    bit1 :not_delegated

    # @!attribute [rw] trusted_for_delegation
    #   @return [BinData::Bit1] This bit is used by the Kerberos protocol. It indicates that the "OK as Delegate" ticket flag (described in[RFC4120] section 2.8) is to be set.
    bit1 :trusted_for_delegation

    # @!attribute [rw] smartcard_required
    #   @return [BinData::Bit1] Specifies that the user can authenticate only with a smart card.
    bit1 :smartcard_required

    # @!attribute [rw] encrypted_test_password_allowed
    #   @return [BinData::Bit1] Specifies that the cleartext password is to be persisted.
    bit1 :encrypted_test_password_allowed

    # @!attribute [rw] account_auto_lock
    #   @return [BinData::Bit1] Specifies that the account has been locked out.
    bit1 :account_auto_lock

    # @!attribute [rw] dont_expire_password
    #   @return [BinData::Bit1] Specifies that the maximum-password-age policy does not apply to this user.
    bit1 :dont_expire_password

    # @!attribute [rw] server_trust_account
    #   @return [BinData::Bit1] Specifies that the object is a DC.
    bit1 :server_trust_account

    # @!attribute [rw] workstation_trust_account
    #   @return [BinData::Bit1] Specifies that the object is a member workstation or server.
    bit1 :workstation_trust_account

    # @!attribute [rw] interdomain_trust_account
    #   @return [BinData::Bit1] Specifies that the object represents a trust object. For more information about trust objects, see [MS-LSAD].
    bit1 :interdomain_trust_account

    # @!attribute [rw] mns_logon_account
    #   @return [BinData::Bit1] This bit is ignored by clients and servers.
    bit1 :mns_logon_account

    # @!attribute [rw] normal_account
    #   @return [BinData::Bit1] Specifies that the user is not a computer object.
    bit1 :normal_account

    # @!attribute [rw] temp_duplicate_account
    #   @return [BinData::Bit1] This bit is ignored by clients and servers.
    bit1 :temp_duplicate_account

    # @!attribute [rw] password_not_required
    #   @return [BinData::Bit1] Specifies that the password-length policy does not apply to this user.
    bit1 :password_not_required

    # @!attribute [rw] home_directory_required
    #   @return [BinData::Bit1] Specifies that the homeDirectory attribute is required.
    bit1 :home_directory_required

    # @!attribute [rw] account_disabled
    #   @return [BinData::Bit1] Specifies that the account is not enabled for authentication.
    bit1 :account_disabled
  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/1c0d6e11-6443-4846-b744-f9f810a504eb
  #
  # [MS-ADA3] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/4517e835-3ee6-44d4-bb95-a94b6966bfb0
  class UpnDnsInfoAttributes < BinData::Record
    endian :big

    30.times do
      bit1 :"_reserved_#{self.fields.length}"
    end

    # @!attribute [rw] sam_name_and_sid
    #   @return [BinData::Bit1] The UPN_DNS_INFO structure has been extended with the user account’s SAM Name and SID.
    bit1 :sam_name_and_sid

    # @!attribute [rw] upn_name_constructed
    #   @return [BinData::Bit1] The user account object does not have the userPrincipalName attribute ([MS-ADA3] section 2.349) set. A UPN constructed by concatenating the user name with the DNS domain name of the account domain is provided.
    bit1 :upn_name_constructed
  end

  class Krb5SidAndAttributesPtr < RubySMB::Dcerpc::Ndr::NdrConfArray
    default_parameters byte_align: 1, type: :krb5_sid_and_attributes

    extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/e465cb27-4bc1-4173-8be0-b5fd64dc9ff7
  class Krb5ClientInfo < BinData::Record
    endian :little
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: Krb5PacElementType::CLIENT_INFORMATION

    # @!attribute [rw] client_id
    #   @return [FileTime] Kerberos initial ticket-granting ticket (TGT) authentication time
    file_time :client_id

    # @!attribute [rw] name_length
    #   @return [Integer]
    uint16 :name_length, initial_value: -> { name.num_bytes }

    # @!attribute [rw] name
    #   @return [String]
    string16 :name, read_length: :name_length
  end

  class Krb5SignatureType < BinData::Uint32le
    # @param [Integer] val The checksum value
    # @see Rex::Proto::Kerberos::Crypto::Checksum
    def assign(val)
      # Handle the scenario of users setting the signature type to a negative value such as -138 for HMAC_RC4
      # Convert it to two's complement representation explicitly to bypass bindata's clamping logic in the super method:
      if val < 0
        val &= 0xffffffff
      end

      super(val)
    end
  end

  class Krb5PacSignatureData < BinData::Record
    endian :little

    # @!attribute [rw] signature_type
    #   @return [Integer] Defines the cryptographic system used to calculate the checksum
    # @see Rex::Proto::Kerberos::Crypto::Checksum
    krb5_signature_type :signature_type

    # @!attribute [rw] signature
    #   @return [String]
    string :signature, length: -> { CHECKSUM_SIGNATURE_LENGTH.fetch(signature_type) }
  end

  class Krb5PacServerChecksum < Krb5PacSignatureData
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: Krb5PacElementType::SERVER_CHECKSUM
  end

  class Krb5PacPrivServerChecksum < Krb5PacSignatureData
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: Krb5PacElementType::PRIVILEGE_SERVER_CHECKSUM
  end

  class Krb5TicketChecksum < Krb5PacSignatureData
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: Krb5PacElementType::TICKET_CHECKSUM
  end

  class Krb5FullPacChecksum < Krb5PacSignatureData
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: Krb5PacElementType::FULL_PAC_CHECKSUM
  end

  # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73
  class Krb5ValidationInfo < RubySMB::Dcerpc::Ndr::NdrStruct
    default_parameters byte_align: 8

    endian :little

    # @!attribute [rw] logon_time
    #   @return [FileTime] User account's lastLogon attributeÏ
    ndr_file_time :logon_time

    # @!attribute [rw] logoff_time
    #   @return [FileTime] Time the client's logon session is set to expire
    ndr_file_time :logoff_time, initial_value: NEVER_EXPIRE

    # @!attribute [rw] kick_off_time
    #   @return [FileTime] logoff_time minus the user account's forceLogoff attribute
    ndr_file_time :kick_off_time, initial_value: NEVER_EXPIRE

    # @!attribute [rw] password_last_set
    #   @return [FileTime] User account's pwdLastSet attribute
    ndr_file_time :password_last_set

    # @!attribute [rw] password_can_change
    #   @return [FileTime] Time at which the client's password is allowed to change
    ndr_file_time :password_can_change

    # @!attribute [rw] password_must_change
    #   @return [FileTime] Time at which the client's password expires
    ndr_file_time :password_must_change, initial_value: NEVER_EXPIRE

    # @!attribute [rw] effective_name
    #   @return [RpcUnicodeString] User account's samAccountName attribute
    rpc_unicode_string :effective_name

    # @!attribute [rw] full_name
    #   @return [RpcUnicodeString] User account's full name for interactive logon
    rpc_unicode_string :full_name

    # @!attribute [rw] logon_script
    #   @return [RpcUnicodeString] User account's scriptPath attribute
    rpc_unicode_string :logon_script

    # @!attribute [rw] profile_path
    #   @return [RpcUnicodeString] User account's profilePath attribute
    rpc_unicode_string :profile_path

    # @!attribute [rw] home_directory
    #   @return [RpcUnicodeString]  User account's HomeDirectory attribute
    rpc_unicode_string :home_directory

    # @!attribute [rw] home_directory_drive
    #   @return [RpcUnicodeString] User account's HomeDrive attribute
    rpc_unicode_string :home_directory_drive

    # @!attribute [rw] logon_count
    #   @return [Integer] User account's LogonCount attribute
    ndr_uint16 :logon_count

    # @!attribute [rw] bad_password_count
    #   @return [Integer] User account's badPwdCount attribute
    ndr_uint16 :bad_password_count

    # @!attribute [rw] user_id
    #   @return [Integer] RID of the account
    ndr_uint32 :user_id

    # @!attribute [rw] primary_group_id
    #   @return [Integer] RID for the primary group to which this account belongs
    ndr_uint32 :primary_group_id

    # @!attribute [rw] group_count
    #   @return [Integer] Number of groups within the account domain to which the account belongs
    ndr_uint32 :group_count, initial_value: -> { group_memberships.length }

    # @!attribute [rw] group_memberships
    #   @return [Integer] List of GROUP_MEMBERSHIP structures that contains the groups to which the account belongs in the account domain
    pgroup_membership_array :group_memberships, type: [:group_membership, { byte_align: 4 }]

    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73
    # @!attribute [rw] user_flags
    #   @return [Integer] A set of bit flags that describe the user's logon information
    ndr_uint32 :user_flags,
               initial_value: -> do
                 value = 0
                 # Bit D: Indicates that the ExtraSids field is populated and contains additional SIDs.
                 value |= (1 << 5) if self.sid_count > 0
                 # Bit H: Indicates that the ResourceGroupIds field is populated.
                 value |= (1 << 9) if self.resource_group_count > 0
                 value
               end

    # @!attribute [rw] user_session_key
    #   @return [Integer] A session key that is used for cryptographic operations on a session
    user_session_key :user_session_key

    # @!attribute [rw] logon_server
    #   @return [RpcUnicodeString] NetBIOS name of the Kerberos KDC that performed the authentication server (AS) ticket request
    rpc_unicode_string :logon_server

    # @!attribute [rw] logon_domain_name
    #   @return [RpcUnicodeString] NetBIOS name of the domain to which this account belongs
    rpc_unicode_string :logon_domain_name

    # @!attribute [rw] logon_domain_id
    #   @return [Integer] SID for the domain specified in LogonDomainName
    prpc_sid :logon_domain_id

    # @!attribute [rw] reserved_1
    #   @return [Integer] This member is reserved
    # ndr_uint64 :reserved_1
    ndr_fix_array :reserved_1, initial_length: 2, type: :ndr_uint32

    # @!attribute [rw] user_account_control
    #   @return [Integer] Set of bit flags that represent information about this account
    ndr_uint32 :user_account_control, initial_value: USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD

    # @!attribute [rw] sub_auth_status
    #   @return [Integer] Subauthentication package's status code
    ndr_uint32 :sub_auth_status

    # @!attribute [rw] last_successful_i_logon
    #   @return [FileTime] User account's msDS-LastSuccessfulInteractiveLogonTime
    ndr_file_time :last_successful_i_logon

    # @!attribute [rw] last_failed_i_logon
    #   @return [FileTime] User account's msDS-LastFailedInteractiveLogonTime
    ndr_file_time :last_failed_i_logon

    # @!attribute [rw] failed_i_logon_count
    #   @return [Integer] User account's msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon
    ndr_uint32 :failed_i_logon_count

    # @!attribute [rw] reserved_3
    #   @return [Integer] This member is reserved
    ndr_uint32 :reserved_3

    # @!attribute [rw] sid_count
    #   @return [Integer] Total number of SIDs present in the ExtraSids member
    ndr_uint32 :sid_count, initial_value: -> { extra_sids.length }

    # @!attribute [rw] extra_sids
    #   @return [Integer] A list of KERB_SID_AND_ATTRIBUTES structures that contain a list of SIDs
    #   corresponding to groups in domains other than the account domain to which the principal belongs
    krb5_sid_and_attributes_ptr :extra_sids # :extra_sids_ptr

    # @!attribute [rw] resource_group_domain_sid
    #   @return [Integer] SID of the domain for the server whose resources the client is authenticating to
    prpc_sid :resource_group_domain_sid # :resource_group_domain_sid_ptr

    # @!attribute [rw] resource_group_count
    #   @return [Integer] Number of resource group identifiers stored in ResourceGroupIds
    ndr_uint32 :resource_group_count

    # @!attribute [rw] resource_group_ids_ptr
    #   @return [Integer] Pointer to list of GROUP_MEMBERSHIP structures that contain the RIDs and attributes of the
    #   account's groups in the resource domain
    pgroup_membership_array :resource_group_ids_ptr, type: [:group_membership, { byte_align: 4 }]

    def group_ids=(group_ids)
      self.group_memberships = group_ids.map do |id|
        { relative_id: id, attributes: SE_GROUP_ALL }
      end
    end
  end

  class Krb5ValidationInfoPtr < Krb5ValidationInfo
    default_parameters byte_align: 8
    extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
  end

  class Krb5LogonInformation < RubySMB::Dcerpc::Ndr::TypeSerialization1
    endian :little
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present
    virtual :ul_type, value: Krb5PacElementType::LOGON_INFORMATION

    krb5_validation_info_ptr :data
  end

  class UnknownPacElement < BinData::Record
    mandatory_parameter :data_length, :selection
    endian :little

    # @!attribute [rw] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: :selection

    # @!attribute [rw] unknown_element
    #   @return [String] The contents of an unknown Pac Element
    string :unknown_element, read_length: :data_length
  end

  # See [2.6.4 NTLM_SUPPLEMENTAL_CREDENTIAL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/39f588d6-21e3-4e09-a9f2-d8f7b9b998bf)
  class Krb5NtlmSupplementalCredential < RubySMB::Dcerpc::Ndr::NdrStruct
    # The only package name that Microsoft KDCs use is `NTLM`
    # See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/a1c36b00-1fca-415c-a4ca-e66e98844760#Appendix_A_16
    PACKAGE_NAME = 'NTLM'.encode('utf-16le').freeze

    default_parameter byte_align: 4
    endian :little

    ndr_uint32 :version
    ndr_uint32 :flags
    ndr_fixed_byte_array :lm_password, initial_length: 16
    ndr_fixed_byte_array :nt_password, initial_length: 16
  end

  class Krb5SecpkgSupplementalCredByteArrayPtr < RubySMB::Dcerpc::Ndr::NdrConfArray
    default_parameters type: :ndr_uint8
    extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
  end

  # See [2.6.3 SECPKG_SUPPLEMENTAL_CRED](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/50974dc7-6bce-4db5-805b-8dca924ad5a4)
  class Krb5SecpkgSupplementalCred < RubySMB::Dcerpc::Ndr::NdrStruct
    default_parameter byte_align: 4
    endian :little

    rpc_unicode_string :package_name
    ndr_uint32 :credential_size
    krb5_secpkg_supplemental_cred_byte_array_ptr :credentials
  end

  # See [2.6.2 PAC_CREDENTIAL_DATA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/4927158e-c9d5-493d-a3f6-1826b88d22ba)
  class Krb5PacCredentialData < RubySMB::Dcerpc::Ndr::NdrStruct
    default_parameter byte_align: 4
    endian :little

    ndr_uint32 :credential_count
    ndr_conf_array :credentials, type: :krb5_secpkg_supplemental_cred

    # Extract the NTLM hash from the credentials array if present
    #
    # @return [String, nil] The NTLM hash as "LMHASH:NTHASH" or `nil` if the
    #   credentials array does not contain any NTLM hash
    def extract_ntlm_hash
      credential = credentials.find do |credential|
        credential.package_name.to_s == Krb5NtlmSupplementalCredential::PACKAGE_NAME
      end
      return unless credential

      ntlm_creds_raw = credential.credentials.to_ary.pack('C*')
      ntlm_creds = Krb5NtlmSupplementalCredential.read(ntlm_creds_raw)
      if ntlm_creds.lm_password.any? {|elem| elem != 0}
        lm_hash = ntlm_creds.lm_password.to_hex
      else
        # Empty LMHash
        lm_hash = 'aad3b435b51404eeaad3b435b51404ee'
      end
      nt_hash = ntlm_creds.nt_password.to_hex

      return "#{lm_hash}:#{nt_hash}"
    end
  end

  class Krb5PacCredentialDataPtr < Krb5PacCredentialData
    extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
  end

  class Krb5SerializedPacCredentialData < RubySMB::Dcerpc::Ndr::TypeSerialization1
    endian :little

    krb5_pac_credential_data_ptr :data
  end

  # See [2.6.1 PAC_CREDENTIAL_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/cc919d0c-f2eb-4f21-b487-080c486d85fe)
  class Krb5PacCredentialInfo < BinData::Record
    mandatory_parameter :data_length
    endian :little
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present
    virtual :ul_type, value: Krb5PacElementType::CREDENTIAL_INFORMATION

    uint32 :version
    uint32 :encryption_type
    array  :serialized_data, type: :uint8, read_until: -> { index == data_length - version.num_bytes - encryption_type.num_bytes - 1 }

    def decrypt_serialized_data(key)
      encryptor = Rex::Proto::Kerberos::Crypto::Encryption::from_etype(self.encryption_type)
      decrypted_serialized_data = encryptor.decrypt(
        self.serialized_data.to_binary_s,
        key,
        Rex::Proto::Kerberos::Crypto::KeyUsage::KERB_NON_KERB_SALT
      )
      Krb5SerializedPacCredentialData.read(decrypted_serialized_data)
    end
  end

  # See [2.10 UPN_DNS_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/1c0d6e11-6443-4846-b744-f9f810a504eb)
  class Krb5UpnDnsInfo < BinData::Record
    auto_call_delayed_io
    endian :little
    # @!attribute [r] ul_type
    #   @return [Integer] Describes the type of data present in the buffer
    virtual :ul_type, value: Krb5PacElementType::USER_PRINCIPAL_NAME_AND_DNS_INFORMATION

    # @!attribute [rw] upn_length
    #   @return [Integer] The length of the UPN
    uint16 :upn_length, value: -> { upn.num_bytes }

    # @!attribute [rw] upn_offset
    #   @return [Integer] The relative offset of the UPN from the beginning of this structure
    uint16 :upn_offset

    # @!attribute [rw] dns_domain_name_length
    #   @return [Integer] The length of the DNS domain name
    uint16 :dns_domain_name_length, value: -> { dns_domain_name.num_bytes }

    # @!attribute [rw] dns_domain_name_offset
    #   @return [Integer] The relative offset of the DNS domain name from the beginning of this structure
    uint16 :dns_domain_name_offset

    # @!attribute [rw] flags
    #   @return [Integer]
    #   U flag (bit 0) The user account object does not have the userPrincipalName attribute.
    #   S flag (bit 1) The structure has been extended with the user account’s SAM Name and SID.
    #   The remaining bits are ignored.
    uint32 :flags

    # @!attribute [rw] sam_name_length
    #   @return [Integer] The length of the SAM name
    #   Only available if the S flag is set
    uint16 :sam_name_length, value: -> { sam_name.num_bytes }, onlyif: :has_s_flag?

    # @!attribute [rw] sam_name_offset
    #   @return [Integer] The relative offset of the SAM name from the beginning of this structure
    #   Only available if the S flag is set
    uint16 :sam_name_offset, onlyif: :has_s_flag?

    # @!attribute [rw] sid_length
    #   @return [Integer] The length of the SID
    #   Only available if the S flag is set
    uint16 :sid_length, value: -> { sid.num_bytes }, onlyif: :has_s_flag?

    # @!attribute [rw] sid_offset
    #   @return [Integer] The relative offset of the SID from the beginning of this structure
    #   Only available if the S flag is set
    uint16 :sid_offset, onlyif: :has_s_flag?

    # @!attribute [rw] upn
    #   @return [String] The UPN (User Principal Name) (e.g. test@windomain.local)
    delayed_io :upn, read_abs_offset: -> { self.abs_offset + upn_offset } do
      string16 read_length: :upn_length
    end

    # @!attribute [rw] dns_domain_name
    #   @return [String] The DNS Domain Name (e.g. WINDOMAIN.LOCAL)
    delayed_io :dns_domain_name, read_abs_offset: -> { self.abs_offset + dns_domain_name_offset } do
      string16 read_length: :dns_domain_name_length
    end

    # @!attribute [rw] sam_name
    #   @return [String] The SAM Name (e.g. test)
    delayed_io :sam_name, read_abs_offset: -> { self.abs_offset + sam_name_offset }, onlyif: -> { has_s_flag? } do
      string16 read_length: :sam_name_length
    end

    # @!attribute [rw] sid
    #   @return [MsDtypSid] The SID (e.g. S-1-5-32-544)
    delayed_io :sid, read_abs_offset: -> { self.abs_offset + sid_offset }, onlyif: -> { has_s_flag? } do
      ms_dtyp_sid
    end

    # def initialize_instance(*args)
    #   super
    #   set_offsets!
    # end
    # @return [Boolean] Returns the value of the S flag
    def has_s_flag?
      flags.anybits?(0b10)
    end

    # @param [Boolean] bool The value to set the S flag to
    # @return [void]
    def set_s_flag(bool)
      set_flag_bit(1, bool)
    end

    # @return [Boolean] Returns the value of the U flag
    def has_u_flag?
      flags.anybits?(0b01)
    end

    # @param [Boolean] bool The value to set the U flag to
    # @return [void]
    def set_u_flag(bool)
      set_flag_bit(0, bool)
    end

    # @param [Integer] upn The relative offset for the upn
    # @param [Integer] dns_domain_name The relative offset for the dns_domain_name
    # @param [Integer] sam_name The relative offset for the sam_name
    # @param [Integer] sid The relative offset for the sid
    # @return [void]
    #
    # Allows you to specify the offsets for the contents, otherwise defaults them
    def set_offsets!(upn: nil, dns_domain_name: nil, sam_name: nil, sid: nil)
      self.upn_offset = upn || calc_upn_offset
      self.dns_domain_name_offset = dns_domain_name || calc_dns_domain_name_offset
      self.sam_name_offset = sam_name || calc_sam_name_offset
      self.sid_offset = sid || calc_sid_offset
    end

    private

    def set_flag_bit(position, bool)
      if bool
        self.flags |= (1 << position)
      else
        self.flags &= ~(1 << position)
      end
    end

    def calc_upn_offset
      has_s_flag? ? 24 : 16
    end

    def calc_dns_domain_name_offset
      upn_offset + upn_length
    end

    def calc_sam_name_offset
      dns_domain_name_offset + dns_domain_name_length
    end

    def calc_sid_offset
      sam_name_offset + sam_name_length
    end
  end

  class Krb5PacElement < BinData::Choice
    mandatory_parameter :data_length

    krb5_logon_information Krb5PacElementType::LOGON_INFORMATION
    krb5_client_info Krb5PacElementType::CLIENT_INFORMATION
    krb5_pac_server_checksum Krb5PacElementType::SERVER_CHECKSUM
    krb5_pac_priv_server_checksum Krb5PacElementType::PRIVILEGE_SERVER_CHECKSUM
    krb5_ticket_checksum Krb5PacElementType::TICKET_CHECKSUM
    krb5_full_pac_checksum Krb5PacElementType::FULL_PAC_CHECKSUM
    krb5_pac_credential_info Krb5PacElementType::CREDENTIAL_INFORMATION, data_length: :data_length
    krb5_upn_dns_info Krb5PacElementType::USER_PRINCIPAL_NAME_AND_DNS_INFORMATION
    unknown_pac_element :default, data_length: :data_length, selection: :selection
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
      krb5_pac_element :pac_element, selection: -> { ul_type }, data_length: :cb_buffer_size
      string :padding, length: -> { num_bytes_to_align(pac_element.num_bytes) }
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
    # @param [String] service_key Service key to calculate the server checksum
    # @param [String] krbtgt_key key to calculate priv server (KDC) and full checksums with, if not specified `service_key` is used
    #
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/962edb93-fa3c-48ea-a0a6-062f760eb69c
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/37bf87b9-1d56-475a-b2b2-e3948b29194d
    def calculate_checksums!(service_key: nil, krbtgt_key: nil)
      server_checksum = nil
      priv_server_checksum = nil
      full_pac_checksum = nil
      pac_info_buffers.each do |info_buffer|
        pac_element = info_buffer.buffer.pac_element
        case pac_element.ul_type
        when Krb5PacElementType::SERVER_CHECKSUM
          server_checksum = pac_element
        when Krb5PacElementType::PRIVILEGE_SERVER_CHECKSUM
          priv_server_checksum = pac_element
        when Krb5PacElementType::FULL_PAC_CHECKSUM
          full_pac_checksum = pac_element
        else
          next
        end
      end

      missing_checksums = []
      missing_checksums << Krb5PacElementType::SERVER_CHECKSUM if server_checksum.nil?
      missing_checksums << Krb5PacElementType::PRIVILEGE_SERVER_CHECKSUM if priv_server_checksum.nil?
      raise Rex::Proto::Kerberos::Pac::Error::MissingInfoBuffer.new(ul_types: missing_checksums) unless missing_checksums.empty?

      if krbtgt_key.nil?
        krbtgt_key = service_key
      end

      # https://bugzilla.samba.org/show_bug.cgi?id=15231
      # https://i.blackhat.com/EU-22/Thursday-Briefings/EU-22-Tervoort-Breaking-Kerberos-RC4-Cipher-and-Spoofing-Windows-PACs-wp.pdf
      if full_pac_checksum
        full_pac_checksum.signature = calculate_checksum(full_pac_checksum.signature_type, krbtgt_key, to_binary_s)
      end

      server_checksum.signature = calculate_checksum(server_checksum.signature_type, service_key, to_binary_s)

      priv_server_checksum.signature = calculate_checksum(priv_server_checksum.signature_type, krbtgt_key, server_checksum.signature)
    end

    # Calculates the offsets for pac_elements if they haven't yet been set
    def calculate_offsets!
      offset = pac_info_buffers.abs_offset + pac_info_buffers.num_bytes
      pac_info_buffers.each do |pac_info|
        next unless pac_info.offset == 0

        pac_info.offset = offset
        offset += pac_info.cb_buffer_size
        offset += num_bytes_to_align(offset)
      end
    end

    # Call this when you are done setting fields in the object
    # in order to finalise the data
    def sign!(service_key: nil, krbtgt_key: nil)
      calculate_offsets!
      calculate_checksums!(service_key: service_key, krbtgt_key: krbtgt_key)
    end

    def calculate_checksum(signature_type, key, data)
      checksummer = Rex::Proto::Kerberos::Crypto::Checksum.from_checksum_type(signature_type)
      checksummer.checksum(key, Rex::Proto::Kerberos::Crypto::KeyUsage::KERB_NON_KERB_CKSUM_SALT, data)
    end

    private

    def num_bytes_to_align(n, align: 8)
      (align - (n % align)) % align
    end
  end
end
