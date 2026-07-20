# -*- coding: binary -*-

require 'bindata'
require 'ruby_smb'
require 'rex/proto/secauthz/well_known_sids'

module Rex::Proto::MsDtyp
  class SDDLParseError < Rex::RuntimeError
  end

  # [2.4.3 ACCESS_MASK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b)
  class MsDtypAccessMask < BinData::Record
    endian :little
    hide   :reserved0, :reserved1

    # the protocol field id reserved for protocol-specific access rights
    uint16 :protocol

    bit3   :reserved0
    bit1   :sy
    bit1   :wo
    bit1   :wd
    bit1   :rc
    bit1   :de

    bit1   :gr
    bit1   :gw
    bit1   :gx
    bit1   :ga
    bit2   :reserved1
    bit1   :ma
    bit1   :as

    ALL  = MsDtypAccessMask.new({ gr: 1, gw: 1, gx: 1, ga: 1, ma: 1, as: 1, sy: 1, wo: 1, wd: 1, rc: 1, de: 1, protocol: 0xffff })
    NONE = MsDtypAccessMask.new({ gr: 0, gw: 0, gx: 0, ga: 0, ma: 0, as: 0, sy: 0, wo: 0, wd: 0, rc: 0, de: 0, protocol: 0 })

    # Obtain an array of the abbreviated names of permissions that the access mask specifies.
    #
    # @return Returns nil if the permissions can't be represented as an array of abbreviations.
    # @rtype [Array<Symbol>, nil]
    def permissions
      if (protocol & 0b1111111000000000) != 0 || ma == 1 || as == 1
        return nil
      end

      permissions = []
      permissions << :GA if ga == 1
      permissions << :GR if gr == 1
      permissions << :GW if gw == 1
      permissions << :GX if gx == 1

      file_access_mask = protocol & 0b000111111111
      permissions << :FA if file_access_mask == 0b000111111111 && de == 1 && rc == 1 && wd == 1 && wo == 1 && sy == 1
      permissions << :FR if file_access_mask == 0b000010001001
      permissions << :FW if file_access_mask == 0b000100010110
      permissions << :FX if file_access_mask == 0b000010100000

      # windows does not reduce registry access flags (i.e. KA, KR, KW) so ignore them here to match it

      permissions << :CC if (protocol & 0b000000000001) != 0 && !permissions.include?(:FA) && !permissions.include?(:FR)
      permissions << :DC if (protocol & 0b000000000010) != 0 && !permissions.include?(:FA) && !permissions.include?(:FW)
      permissions << :LC if (protocol & 0b000000000100) != 0 && !permissions.include?(:FA) && !permissions.include?(:FW)
      permissions << :SW if (protocol & 0b000000001000) != 0 && !permissions.include?(:FA) && !permissions.include?(:FR)
      permissions << :RP if (protocol & 0b000000010000) != 0 && !permissions.include?(:FA) && !permissions.include?(:FW)
      permissions << :WP if (protocol & 0b000000100000) != 0 && !permissions.include?(:FA) && !permissions.include?(:FX)
      permissions << :DT if (protocol & 0b000001000000) != 0 && !permissions.include?(:FA)
      permissions << :LO if (protocol & 0b000010000000) != 0 && !permissions.include?(:FA)
      permissions << :CR if (protocol & 0b000100000000) != 0 && !permissions.include?(:FA)

      permissions << :SD if de == 1 && !permissions.include?(:FA)
      permissions << :RC if rc == 1 && !permissions.include?(:FA)
      permissions << :WD if wd == 1 && !permissions.include?(:FA)
      permissions << :WO if wo == 1 && !permissions.include?(:FA)

      permissions
    end

    def to_sddl_text
      perms = permissions

      if perms.nil?
        # if one of these conditions are true, we can't reduce this to a set of flags so dump it as hex
        return "0x#{to_binary_s.unpack1('L<').to_s(16).rjust(8, '0')}"
      end


      permissions.map(&:to_s).join
    end

    def self.from_sddl_text(sddl_text)
      if sddl_text =~ /\A0x[0-9a-fA-F]{1,8}\Z/
        return self.read([sddl_text.delete_prefix('0x').to_i(16)].pack('L<'))
      end

      access_mask = self.new
      sddl_text.split(/(G[ARWX]|RC|SD|WD|WO|RP|WP|CC|DC|LC|SW|LO|DT|CR|F[ARWX]|K[ARWX]|N[RWX])/).each do |right|
        case right
        # generic access rights
        when 'GA', 'GR', 'GW', 'GX'
          access_mask.send("#{right.downcase}=", true)
        # standard access rights
        when 'RC'
          access_mask.rc = true
        when 'SD'
          access_mask.de = true
        when 'WD', 'WO'
          access_mask.send("#{right.downcase}=", true)
        # directory service object access rights
        when 'RP'
          access_mask.protocol |= 16
        when 'WP'
          access_mask.protocol |= 32
        when 'CC'
          access_mask.protocol |= 1
        when 'DC'
          access_mask.protocol |= 2
        when 'LC'
          access_mask.protocol |= 4
        when 'SW'
          access_mask.protocol |= 8
        when 'LO'
          access_mask.protocol |= 128
        when 'DT'
          access_mask.protocol |= 64
        when 'CR'
          access_mask.protocol |= 256
        # file access rights
        when 'FA'
          access_mask.protocol |= 0x1ff
          access_mask.de = true
          access_mask.rc = true
          access_mask.wd = true
          access_mask.wo = true
          access_mask.sy = true
        when 'FR'
          access_mask.protocol |= 0x89
        when 'FW'
          access_mask.protocol |= 0x116
        when 'FX'
          access_mask.protocol |= 0xa0
        # registry key access rights
        when 'KA'
          access_mask.protocol |= 0x3f
          access_mask.de = true
          access_mask.rc = true
          access_mask.wd = true
          access_mask.wo = true
        when 'KR'
          access_mask.protocol |= 0x19
        when 'KW'
          access_mask.protocol |= 0x06
        when 'KX'
          access_mask.protocol |= 0x19
        when 'NR', 'NW', 'NX'
          raise SDDLParseError.new('unsupported ACE access right: ' + right)
        when ''
        else
          raise SDDLParseError.new('unknown ACE access right: ' + right)
        end
      end

      access_mask
    end
  end

  # [2.4.2.2 SID--Packet Representation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861)
  class MsDtypSid < BinData::Primitive
    endian :little

    uint8 :revision, initial_value: 1
    uint8 :sub_authority_count, initial_value: -> { self.sub_authority.length }
    array :identifier_authority, type: :uint8, initial_length: 6
    array :sub_authority, type: :uint32, initial_length: :sub_authority_count

    def set(val)
      # allow assignment from the human-readable string representation
      raise ArgumentError.new("Invalid SID: #{val}") unless val.is_a?(String) && val =~ /^S-1-(\d+)(-\d+)*$/

      _, _, ia, sa = val.split('-', 4)
      self.identifier_authority = [ia.to_i].pack('Q>')[2..].bytes
      self.sub_authority = sa.nil? ? [] : sa.split('-').map(&:to_i)
    end

    def get
      str = 'S-1'
      str << "-#{("\x00\x00" + identifier_authority.to_binary_s).unpack1('Q>')}"
      str << '-' + sub_authority.map(&:to_s).join('-') unless sub_authority.empty?
      str
    end

    def rid
      sub_authority.last
    end

    # these can be validated using powershell where ?? is the code
    #   (ConvertFrom-SddlString -Sddl "O:??").RawDescriptor.Owner
    SDDL_SIDS = {
      'AA' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_ACCESS_CONTROL_ASSISTANCE_OPS,                                                                     # SDDL_ACCESS_CONTROL_ASSISTANCE_OPS
      'AC' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_ALL_APP_PACKAGES,                                                                                          # SDDL_ALL_APP_PACKAGES
      'AN' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_ANONYMOUS_LOGON_SID,                                                                                       # SDDL_ANONYMOUS
      'AO' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_ACCOUNT_OPS,                                                                                       # SDDL_ACCOUNT_OPERATORS
      'AP' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_PROTECTED_USERS}",                                                                # SDDL_PROTECTED_USERS
      'AU' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID,                                                                                    # SDDL_AUTHENTICATED_USERS
      'BA' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_ADMINS,                                                                                            # SDDL_BUILTIN_ADMINISTRATORS
      'BG' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_GUESTS,                                                                                            # SDDL_BUILTIN_GUESTS
      'BO' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_BACKUP_OPS,                                                                                        # SDDL_BACKUP_OPERATORS
      'BU' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_USERS,                                                                                             # SDDL_BUILTIN_USERS
      'CA' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_CERT_ADMINS}",                                                                    # SDDL_CERT_SERV_ADMINISTRATORS
      'CD' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_CERTSVC_DCOM_ACCESS_GROUP,                                                                         # SDDL_CERTSVC_DCOM_ACCESS
      'CG' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_CREATOR_GROUP_SID,                                                                                         # SDDL_CREATOR_GROUP
      'CN' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_CLONEABLE_CONTROLLERS}",                                                          # SDDL_CLONEABLE_CONTROLLERS
      'CO' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_CREATOR_OWNER_SID,                                                                                         # SDDL_CREATOR_OWNER
      'CY' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_CRYPTO_OPERATORS,                                                                                  # SDDL_CRYPTO_OPERATORS
      'DA' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ADMINS}",                                                                         # SDDL_DOMAIN_ADMINISTRATORS
      'DC' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_COMPUTERS}",                                                                      # SDDL_DOMAIN_COMPUTERS
      'DD' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_CONTROLLERS}",                                                                    # SDDL_DOMAIN_DOMAIN_CONTROLLERS
      'DG' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_GUESTS}",                                                                         # SDDL_DOMAIN_GUESTS
      'DU' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_USERS}",                                                                          # SDDL_DOMAIN_USERS
      'EA' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ENTERPRISE_ADMINS}",                                                              # SDDL_ENTERPRISE_ADMINS
      'ED' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_ENTERPRISE_CONTROLLERS_SID,                                                                                # SDDL_ENTERPRISE_DOMAIN_CONTROLLERS
      'EK' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ENTERPRISE_KEY_ADMINS}",                                                          # SDDL_ENTERPRISE_KEY_ADMINS
      'ER' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_EVENT_LOG_READERS_GROUP,                                                                           # SDDL_EVENT_LOG_READERS
      'ES' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_RDS_ENDPOINT_SERVERS,                                                                              # SDDL_RDS_ENDPOINT_SERVERS
      'HA' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_HYPER_V_ADMINS,                                                                                    # SDDL_HYPER_V_ADMINS
      'HI' => "S-1-16-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_HIGH_RID}",                                                                            # SDDL_ML_HIGH
      'IS' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_IUSERS,                                                                                            # SDDL_IIS_USERS
      'IU' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_INTERACTIVE_SID,                                                                                           # SDDL_INTERACTIVE
      'KA' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_KEY_ADMINS}",                                                                     # SDDL_KEY_ADMINS
      'LA' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_USER_RID_ADMIN}",                                                                           # SDDL_LOCAL_ADMIN
      'LG' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_USER_RID_GUEST}",                                                                           # SDDL_LOCAL_GUEST
      'LS' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_LOCAL_SERVICE_SID,                                                                                         # SDDL_LOCAL_SERVICE
      'LU' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_LOGGING_USERS,                                                                                     # SDDL_PERFLOG_USERS
      'LW' => "S-1-16-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_LOW_RID}",                                                                             # SDDL_ML_LOW
      'ME' => "S-1-16-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_MEDIUM_RID}",                                                                          # SDDL_ML_MEDIUM
      'MP' => "S-1-16-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_MEDIUM_PLUS_RID}",                                                                     # SDDL_ML_MEDIUM_PLUS
      'MU' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_MONITORING_USERS,                                                                                  # SDDL_PERFMON_USERS
      'NO' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_NETWORK_CONFIGURATION_OPS,                                                                         # SDDL_NETWORK_CONFIGURATION_OPS
      'NS' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_NETWORK_SERVICE_SID,                                                                                       # SDDL_NETWORK_SERVICE
      'NU' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_NETWORK_SID,                                                                                               # SDDL_NETWORK
      'OW' => "#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_CREATOR_SID_AUTHORITY}-4",                                                                              # SDDL_OWNER_RIGHTS
      'PA' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_POLICY_ADMINS}",                                                                  # SDDL_GROUP_POLICY_ADMINS
      'PO' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_PRINT_OPS,                                                                                         # SDDL_PRINTER_OPERATORS
      'PS' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_PRINCIPAL_SELF_SID,                                                                                        # SDDL_PERSONAL_SELF
      'PU' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_POWER_USERS,                                                                                       # SDDL_POWER_USERS
      'RA' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_RDS_REMOTE_ACCESS_SERVERS,                                                                         # SDDL_RDS_REMOTE_ACCESS_SERVERS
      'RC' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_RESTRICTED_CODE_SID,                                                                                       # SDDL_RESTRICTED_CODE
      'RD' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_REMOTE_DESKTOP_USERS,                                                                              # SDDL_REMOTE_DESKTOP
      'RE' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_REPLICATOR,                                                                                        # SDDL_REPLICATOR
      'RM' => "#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_BUILTIN_DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS}",  # SDDL_RMS__SERVICE_OPERATORS
      'RO' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS}",                                         # SDDL_ENTERPRISE_RO_DCs
      'RS' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_RAS_SERVERS}",                                                                    # SDDL_RAS_SERVERS
      'RU' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_PREW2KCOMPACCESS,                                                                                  # SDDL_ALIAS_PREW2KCOMPACC
      'SA' => "${DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_SCHEMA_ADMINS}",                                                                  # SDDL_SCHEMA_ADMINISTRATORS
      'SI' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_SYSTEM_SID,                                                                                      # SDDL_ML_SYSTEM
      'SO' => Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_SYSTEM_OPS,                                                                                        # SDDL_SERVER_OPERATORS
      'SS' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATION_SERVICE_ASSERTED_SID,                                                                       # SDDL_SERVICE_ASSERTED
      'SU' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_SERVICE_SID,                                                                                               # SDDL_SERVICE
      'SY' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_LOCAL_SYSTEM_SID,                                                                                          # SDDL_LOCAL_SYSTEM
      'UD' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_USERMODEDRIVERHOST_ID_BASE_SID,                                                                            # SDDL_USER_MODE_DRIVERS
      'WD' => "#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_WORLD_SID_AUTHORITY}-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_WORLD_RID}",                       # SDDL_EVERYONE
      'WR' => Rex::Proto::Secauthz::WellKnownSids::SECURITY_WRITE_RESTRICTED_CODE_SID                                                                                  # SDDL_WRITE_RESTRICTED_CODE
    }.freeze

    private_constant :SDDL_SIDS

    def to_sddl_text(domain_sid: nil)
      sid = to_s

      lookup = domain_sid.blank? ? sid : sid.sub(domain_sid, '${DOMAIN_SID}')
      if (sddl_text = self.class.const_get(:SDDL_SIDS).key(lookup)).nil?
        sddl_text = sid
      end
      # these short names aren't supported by all versions of Windows, avoid compatibility issues by not outputting them
      sddl_text = sid if %w[ AP CN EK KA ].include?(sddl_text)

      sddl_text
    end

    def self.from_sddl_text(sddl_text, domain_sid:)
      # see: https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
      sddl_text = sddl_text.dup.upcase

      if SDDL_SIDS.key?(sddl_text)
        sid_text = SDDL_SIDS[sddl_text].sub('${DOMAIN_SID}', domain_sid)
      elsif sddl_text =~ /^S(-\d+)+/
        sid_text = sddl_text
      else
        raise SDDLParseError.new('invalid SID string: ' + sddl_text)
      end

      self.new(sid_text)
    end
  end

  # [Universal Unique Identifier](http://pubs.opengroup.org/onlinepubs/9629399/apdxa.htm)
  # The online documentation at [2.3.4.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40)
  # weirdly doesn't mention this needs to be 4 byte aligned for us to read it correctly,
  # which the RubySMB::Dcerpc::Uuid definition takes care of.
  class MsDtypGuid < RubySMB::Dcerpc::Uuid
    def self.random_generate
      # Taken from the "D" format as specified in
      # https://learn.microsoft.com/en-us/dotnet/api/system.guid.tostring?view=net-7.0
      "{#{Rex::Text.rand_text_hex(8)}-#{Rex::Text.rand_text_hex(4)}-#{Rex::Text.rand_text_hex(4)}-#{Rex::Text.rand_text_hex(4)}-#{Rex::Text.rand_text_hex(12)}}".downcase
    end
  end

  # Definitions taken from [2.4.4.1 ACE_HEADER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586)
  class MsDtypAceType
    ACCESS_ALLOWED_ACE_TYPE                 = 0x0
    ACCESS_DENIED_ACE_TYPE                  = 0x1
    SYSTEM_AUDIT_ACE_TYPE                   = 0x2
    SYSTEM_ALARM_ACE_TYPE                   = 0x3 # Reserved for future use according to documentation.
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE        = 0x4 # Reserved for future use according to documentation.
    ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 0x5
    ACCESS_DENIED_OBJECT_ACE_TYPE           = 0x6
    SYSTEM_AUDIT_OBJECT_ACE_TYPE            = 0x7
    SYSTEM_ALARM_OBJECT_ACE_TYPE            = 0x8 # Reserved for future use according to documentation.
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 0x9
    ACCESS_DENIED_CALLBACK_ACE_TYPE         = 0xA
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0xC
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE          = 0xD
    SYSTEM_ALARM_CALLBACK_ACE_TYPE          = 0xE # Reserved for future use according to documentation.
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   = 0xF
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   = 0x10 # Reserved for future use according to documentation.
    SYSTEM_MANDATORY_LABEL_ACE_TYPE         = 0x11
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      = 0x12
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        = 0x13

    def self.name(value)
      constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
    end

    def self.alarm?(type)
      [
        SYSTEM_ALARM_ACE_TYPE,
        SYSTEM_ALARM_OBJECT_ACE_TYPE,
        SYSTEM_ALARM_CALLBACK_ACE_TYPE,
        SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
      ].include? type
    end

    def self.allow?(type)
      [
        ACCESS_ALLOWED_ACE_TYPE,
        ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
      ].include? type
    end

    def self.audit?(type)
      [
        SYSTEM_AUDIT_ACE_TYPE,
        SYSTEM_AUDIT_OBJECT_ACE_TYPE,
        SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
        SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
      ].include? type
    end

    def self.deny?(type)
      [
        ACCESS_DENIED_ACE_TYPE,
        ACCESS_DENIED_OBJECT_ACE_TYPE,
        ACCESS_DENIED_CALLBACK_ACE_TYPE,
        ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
      ].include? type
    end

    def self.has_object?(type)
      [
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        ACCESS_DENIED_OBJECT_ACE_TYPE,
        SYSTEM_AUDIT_OBJECT_ACE_TYPE,
        SYSTEM_ALARM_OBJECT_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
        SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
        SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
      ].include? type
    end
  end

  # [2.4.4.1 ACE_HEADER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586)
  class MsDtypAceHeader < BinData::Record
    endian :little

    uint8  :ace_type
    struct :ace_flags do
      bit1 :failed_access_ace_flag
      bit1 :successful_access_ace_flag
      bit1 :critical_ace_flag  # used only with access allowed ACE types, see: https://www.codemachine.com/downloads/win10.1903/ntifs.h
      bit1 :inherited_ace
      bit1 :inherit_only_ace
      bit1 :no_propagate_inherit_ace
      bit1 :container_inherit_ace
      bit1 :object_inherit_ace
    end
    uint16 :ace_size, initial_value: -> { parent&.num_bytes || 0 }
  end

  class MsDtypAceNonObjectBody < BinData::Record
    endian :little

    ms_dtyp_access_mask :access_mask
    ms_dtyp_sid         :sid, byte_align: 4
  end

  class MsDtypAceObjectBody < BinData::Record
    endian :little

    ms_dtyp_access_mask :access_mask
    struct              :flags do
      bit1 :reserved5
      bit1 :reserved4
      bit1 :reserved3
      bit1 :reserved2
      bit1 :reserved1
      bit1 :reserved
      bit1 :ace_inherited_object_type_present
      bit1 :ace_object_type_present
    end
    ms_dtyp_guid        :object_type, onlyif: -> { flags.ace_object_type_present != 0x0 }
    ms_dtyp_guid        :inherited_object_type, onlyif: -> { flags.ace_inherited_object_type_present != 0x0 }
    ms_dtyp_sid         :sid, byte_align: 4
  end

  # [2.4.4.2 ACCESS_ALLOWED_ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb)
  class MsDtypAccessAllowedAceBody < MsDtypAceNonObjectBody
  end

  # [2.4.4.4 ACCESS_DENIED_ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/b1e1321d-5816-4513-be67-b65d8ae52fe8)
  class MsDtypAccessDeniedAceBody < MsDtypAceNonObjectBody
  end

  # [2.4.4.10 SYSTEM_AUDIT_ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/9431fd0f-5b9a-47f0-b3f0-3015e2d0d4f9)
  class MsDtypSystemAuditAceBody < MsDtypAceNonObjectBody
  end

  # [2.4.4.3 ACCESS_ALLOWED_OBJECT_ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe)
  class MsDtypAccessAllowedObjectAceBody < MsDtypAceObjectBody
  end

  # [2.4.4.5 ACCESS_DENIED_OBJECT_ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/8720fcf3-865c-4557-97b1-0b3489a6c270)
  class MsDtypAccessDeniedObjectAceBody < MsDtypAceObjectBody
  end

  # [2.4.4.11 SYSTEM_AUDIT_OBJECT_ACE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c8da72ae-6b54-4a05-85f4-e2594936d3d5)
  class MsDtypSystemAuditObjectAceBody < MsDtypAceObjectBody
    endian :little

    string             :application_data, read_length: -> { calc_app_data_length }

    def calc_app_data_length
      ace_header = parent&.parent&.header
      ace_body = parent&.parent&.body
      return 0 if ace_header.nil? || ace_body.nil?

      ace_size = ace_header.ace_size
      return 0 if ace_size.nil? or (ace_size == 0)

      ace_header_length = ace_header.to_binary_s.length
      if ace_body.nil?
        return 0 # Read no data as there is no body, so either we have done some data misalignment or we shouldn't be reading data.
      else
        ace_body_length = ace_body.to_binary_s.length
        return ace_size - (ace_header_length + ace_body_length)
      end
    end
  end

  class MsDtypAce < BinData::Record
    endian :little

    ms_dtyp_ace_header :header
    choice             :body, selection: -> { header.ace_type } do
      ms_dtyp_access_allowed_ace_body Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE
      ms_dtyp_access_denied_ace_body Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_DENIED_ACE_TYPE
      ms_dtyp_system_audit_ace_body Rex::Proto::MsDtyp::MsDtypAceType::SYSTEM_AUDIT_ACE_TYPE
      # Type 3 is reserved for future use
      # Type 4 is reserved for future use
      ms_dtyp_access_allowed_object_ace_body Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
      ms_dtyp_access_denied_object_ace_body Rex::Proto::MsDtyp::MsDtypAceType::ACCESS_DENIED_OBJECT_ACE_TYPE
      ms_dtyp_system_audit_object_ace_body Rex::Proto::MsDtyp::MsDtypAceType::SYSTEM_AUDIT_OBJECT_ACE_TYPE
      # Type 8 is reserved for future use
      # Type 14 aka 0xE is reserved for future use
      # Type 16 aka 0x10 is reserved for future use
      string :default, read_length: -> { header.ace_size - body.rel_offset }
    end

    def to_sddl_text(domain_sid: nil)
      parts = []

      case header.ace_type
      when MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE
        parts << 'A'
      when MsDtypAceType::ACCESS_DENIED_ACE_TYPE
        parts << 'D'
      when MsDtypAceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
        parts << 'OA'
      when MsDtypAceType::ACCESS_DENIED_OBJECT_ACE_TYPE
        parts << 'OD'
      when MsDtypAceType::SYSTEM_AUDIT_ACE_TYPE
        parts << 'AU'
      when MsDtypAceType::SYSTEM_AUDIT_OBJECT_ACE_TYPE
        parts << 'OU'
      else
        raise SDDLParseError.new('unknown ACE type: ' + header.ace_type.to_i)
      end

      ace_flags = ''
      ace_flags << 'OI' if header.ace_flags.object_inherit_ace == 1
      ace_flags << 'CI' if header.ace_flags.container_inherit_ace == 1
      ace_flags << 'IO' if header.ace_flags.inherit_only_ace == 1

      ace_flags << 'NP' if header.ace_flags.no_propagate_inherit_ace == 1
      ace_flags << 'ID' if header.ace_flags.inherited_ace == 1
      ace_flags << 'SA' if header.ace_flags.successful_access_ace_flag == 1
      ace_flags << 'FA' if header.ace_flags.failed_access_ace_flag == 1
      ace_flags << 'CR' if header.ace_flags.critical_ace_flag == 1
      parts << ace_flags

      parts << body.access_mask.to_sddl_text

      if body[:flags]
        parts << (body.flags[:ace_object_type_present] == 1 ? body.object_type.to_s : '')
        parts << (body.flags[:ace_inherited_object_type_present] == 1 ? body.inherited_object_type.to_s : '')
      else
        parts << ''
        parts << ''
      end

      if body.sid?
        parts << body.sid.to_sddl_text(domain_sid: domain_sid)
      else
        parts << ''
      end

      parts.join(';')
    end

    def self.from_sddl_text(sddl_text, domain_sid:)
      parts = sddl_text.upcase.split(';', -1)
      raise SDDLParseError.new('too few ACE fields') if parts.length < 6
      raise SDDLParseError.new('too many ACE fields') if parts.length > 7

      ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = parts[0...6]
      resource_attribute = parts[6]

      ace = self.new
      case ace_type
      when 'A'
        ace.header.ace_type = MsDtypAceType::ACCESS_ALLOWED_ACE_TYPE
      when 'D'
        ace.header.ace_type = MsDtypAceType::ACCESS_DENIED_ACE_TYPE
      when 'OA'
        ace.header.ace_type = MsDtypAceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
      when 'OD'
        ace.header.ace_type = MsDtypAceType::ACCESS_DENIED_OBJECT_ACE_TYPE
      when 'AU'
        ace.header.ace_type = MsDtypAceType::SYSTEM_AUDIT_ACE_TYPE
      when 'OU'
        ace.header.ace_type = MsDtypAceType::SYSTEM_AUDIT_OBJECT_ACE_TYPE
      when 'AL', 'OL', 'ML', 'XA', 'SD', 'RA', 'SP', 'XU', 'ZA', 'TL', 'FL'
        raise SDDLParseError.new('unsupported ACE type: ' + ace_type)
      else
        raise SDDLParseError.new('unknown ACE type: ' + ace_type)
      end

      ace_flags.split(/(CI|OI|NP|IO|ID|SA|FA|TP|CR)/).each do |flag|
        case flag
        when 'CI'
          ace.header.ace_flags.container_inherit_ace = true
        when 'OI'
          ace.header.ace_flags.object_inherit_ace = true
        when 'NP'
          ace.header.ace_flags.no_propagate_inherit_ace = true
        when 'IO'
          ace.header.ace_flags.inherit_only_ace = true
        when 'ID'
          ace.header.ace_flags.inherited_ace = true
        when 'SA'
          ace.header.ace_flags.successful_access_ace_flag = true
        when 'FA'
          ace.header.ace_flags.failed_access_ace_flag = true
        when 'TP'
          raise SDDLParseError.new('unsupported ACE flag: TP')
        when 'CR'
          ace.header.ace_flags.critical_ace_flag = true
        when ''
        else
          raise SDDLParseError.new('unknown ACE flag: ' + flag)
        end
      end

      ace.body.access_mask = MsDtypAccessMask.from_sddl_text(rights)

      unless object_guid.blank?
        begin
          guid = MsDtypGuid.new(object_guid)
        rescue StandardError
          raise SDDLParseError.new('invalid object GUID: ' + object_guid)
        end

        unless ace.body.respond_to?('object_type=')
          raise SDDLParseError.new('setting object type for incompatible ACE type')
        end
        ace.body.flags.ace_object_type_present = true
        ace.body.object_type = guid
      end

      unless inherit_object_guid.blank?
        begin
          guid = MsDtypGuid.new(inherit_object_guid)
        rescue StandardError
          raise SDDLParseError.new('invalid inherited object GUID: ' + inherit_object_guid)
        end

        unless ace.body.respond_to?('inherited_object_type=')
          raise SDDLParseError.new('setting inherited object type for incompatible ACE type')
        end
        ace.body.flags.ace_inherited_object_type_present = true
        ace.body.inherited_object_type = guid
      end

      unless account_sid.blank?
        ace.body.sid = MsDtypSid.from_sddl_text(account_sid, domain_sid: domain_sid)
      end

      unless resource_attribute.blank?
        raise SDDLParseError.new('unsupported resource attribute: ' + resource_attribute)
      end

      ace
    end
  end

  # [2.4.5 ACL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428)
  class MsDtypAcl < BinData::Record
    ACL_REVISION = 2
    ACL_REVISION_DS = 4

    endian :little

    uint8  :acl_revision, initial_value: ACL_REVISION
    uint8  :sbz1
    uint16 :acl_size, initial_value: -> { num_bytes }
    uint16 :acl_count, initial_value: -> { aces.length }
    uint16 :sbz2
    array  :aces, type: :ms_dtyp_ace, initial_length: :acl_count
  end

  # [2.4.6 SECURITY_DESCRIPTOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d)
  class MsDtypSecurityDescriptor < BinData::Record
    endian :little

    uint8  :revision, initial_value: 1
    uint8  :sbz1
    struct :control do
      bit1 :ss
      bit1 :dt
      bit1 :sd
      bit1 :sp, initial_value: -> { sacl? ? 1 : 0 }
      bit1 :dd
      bit1 :dp, initial_value: -> { dacl? ? 1 : 0 }
      bit1 :gd
      bit1 :od

      bit1 :sr, initial_value: 1
      bit1 :rm
      bit1 :ps
      bit1 :pd
      bit1 :si
      bit1 :di
      bit1 :sc
      bit1 :dc
    end
    uint32 :offset_owner, value: -> { offset_for(:owner_sid) }
    uint32 :offset_group, value: -> { offset_for(:group_sid) }
    uint32 :offset_sacl, value: -> { offset_for(:sacl) }
    uint32 :offset_dacl, value: -> { offset_for(:dacl) }
    rest   :buffer, value: -> { build_buffer }
    hide   :buffer

    def to_sddl_text(domain_sid: nil)
      sddl_text = ''
      sddl_text << "O:#{owner_sid.to_sddl_text(domain_sid: domain_sid)}" if owner_sid?
      sddl_text << "G:#{group_sid.to_sddl_text(domain_sid: domain_sid)}" if group_sid?
      sddl_text << "D:#{dacl_to_sddl_text(domain_sid: domain_sid)}" if dacl?
      sddl_text << "S:#{sacl_to_sddl_text(domain_sid: domain_sid)}" if sacl?

      sddl_text
    end

    def dacl_to_sddl_text(domain_sid: nil)
      sddl_text = ''

      if !dacl?
        sddl_text << 'NO_ACCESS_CONTROL'
      else
        sddl_text << 'P' if control.pd == 1
        sddl_text << 'AR' if control.dc == 1
        sddl_text << 'AI' if control.di == 1
        sddl_text << dacl.aces.map { |ace| "(#{ace.to_sddl_text(domain_sid: domain_sid)})" }.join
      end

      sddl_text
    end

    def sacl_to_sddl_text(domain_sid: nil)
      sddl_text = ''

      if !sacl?
        sddl_text << 'NO_ACCESS_CONTROL'
      else
        sddl_text << 'P' if control.ps == 1
        sddl_text << 'AR' if control.sc == 1
        sddl_text << 'AI' if control.si == 1
        sddl_text << sacl.aces.map { |ace| "(#{ace.to_sddl_text(domain_sid: domain_sid)})" }.join
      end

      sddl_text
    end

    def self.from_sddl_text(sddl_text, domain_sid:)
      sacl_set = dacl_set = false
      sd = self.new
      sddl_text = sddl_text.dup.gsub(/\s/, '')  # start by removing all whitespace
      sddl_text.scan(/([OGDS]:(?:.(?!:))*)/).each do |part,|
        component, _, value = part.partition(':')
        case component
        when 'O'
          if sd.owner_sid.present?
            raise SDDLParseError.new('extra owner SID')
          end

          sd.owner_sid = MsDtypSid.from_sddl_text(value, domain_sid: domain_sid)
        when 'G'
          if sd.group_sid.present?
            raise SDDLParseError.new('extra group SID')
          end

          sd.group_sid = MsDtypSid.from_sddl_text(value, domain_sid: domain_sid)
        when 'D'
          raise SDDLParseError.new('extra DACL') if dacl_set

          value.upcase!
          dacl_set = true
          access_control = true
          flags = value.split('(', 2).first || ''
          flags.split(/(P|AR|AI|NO_ACCESS_CONTROL)/).each do |flag|
            case flag
            when 'AI'
              sd.control.di = true
            when 'AR'
              sd.control.dc = true
            when 'P'
              sd.control.pd = true
            when 'NO_ACCESS_CONTROL'
              access_control = false
            when ''
            else
              raise SDDLParseError.new('unknown DACL flag: ' + flag)
            end
          end

          next unless access_control

          sd.dacl = MsDtypAcl.new
          sd.dacl.aces = self.aces_from_sddl_text(value.delete_prefix(flags), domain_sid: domain_sid)
        when 'S'
          raise SDDLParseError.new('extra SACL') if sacl_set

          value.upcase!
          sacl_set = true
          access_control = true
          flags = value.split('(', 2).first || ''
          flags.split(/(P|AR|AI|NO_ACCESS_CONTROL)/).each do |flag|
            case flag
            when 'AI'
              sd.control.si = true
            when 'AR'
              sd.control.sc = true
            when 'P'
              sd.control.ps = true
            when 'NO_ACCESS_CONTROL'
              access_control = false
            when ''
            else
              raise SDDLParseError.new('unknown SACL flag: ' + flag)
            end
          end

          next unless access_control

          sd.sacl = MsDtypAcl.new
          sd.sacl.aces = self.aces_from_sddl_text(value.delete_prefix(flags), domain_sid: domain_sid)
        else
          raise SDDLParseError.new('unknown directive: ' + part[0])
        end
      end

      sd
    end

    class << self
      private

      def aces_from_sddl_text(aces, domain_sid:)
        ace_regex = /\([^\)]*\)/

        invalid_aces = aces.split(ace_regex).reject(&:empty?)
        unless invalid_aces.empty?
          raise SDDLParseError.new('malformed ACE: ' + invalid_aces.first)
        end

        aces.scan(ace_regex).map do |ace_text|
          MsDtypAce.from_sddl_text(ace_text[1...-1], domain_sid: domain_sid)
        end
      end
    end

    def initialize_shared_instance
      # define accessor methods for the custom fields to expose the same API as BinData
      define_field_accessors_for2(:owner_sid)
      define_field_accessors_for2(:group_sid)
      define_field_accessors_for2(:sacl)
      define_field_accessors_for2(:dacl)
      super
    end

    def initialize_instance
      value = super
      self.owner_sid = get_parameter(:owner_sid)
      self.group_sid = get_parameter(:group_sid)
      self.sacl = get_parameter(:sacl)
      self.dacl = get_parameter(:dacl)
      value
    end

    def do_read(val)
      value = super
      if offset_owner != 0
        @owner_sid = MsDtypSid.read(buffer[offset_owner - buffer.rel_offset..])
      end
      if offset_group != 0
        @group_sid = MsDtypSid.read(buffer[offset_group - buffer.rel_offset..])
      end
      if offset_sacl != 0
        @sacl = MsDtypAcl.read(buffer[offset_sacl - buffer.rel_offset..])
      end
      if offset_dacl != 0
        @dacl = MsDtypAcl.read(buffer[offset_dacl - buffer.rel_offset..])
      end
      value
    end

    def snapshot
      snap = super
      snap[:owner_sid] ||= owner_sid&.snapshot
      snap[:group_sid] ||= group_sid&.snapshot
      snap[:sacl] ||= sacl&.snapshot
      snap[:dacl] ||= dacl&.snapshot
      snap
    end

    def owner_sid=(sid)
      sid = MsDtypSid.new(sid) unless sid.nil? || sid.is_a?(MsDtypSid)
      @owner_sid = sid
    end

    def group_sid=(sid)
      sid = MsDtypSid.new(sid) unless sid.nil? || sid.is_a?(MsDtypSid)
      @group_sid = sid
    end

    attr_accessor :sacl, :dacl
    attr_reader :owner_sid, :group_sid

    private

    BUFFER_FIELD_ORDER = %i[ sacl dacl owner_sid group_sid ]

    def build_buffer
      buf = ''
      BUFFER_FIELD_ORDER.each do |field_name|
        field_value = send(field_name)
        buf << field_value.to_binary_s if field_value
      end
      buf
    end

    def define_field_accessors_for2(name)
      define_singleton_method("#{name}?") do
        !send(name).nil?
      end
    end

    def offset_for(field)
      return 0 unless instance_variable_get("@#{field}")

      offset = buffer.rel_offset
      BUFFER_FIELD_ORDER.each do |cursor|
        break if cursor == field

        cursor = instance_variable_get("@#{cursor}")
        offset += cursor.num_bytes if cursor
      end

      offset
    end
  end

  # [2.3.7 LUID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/48cbee2a-0790-45f2-8269-931d7083b2c3)
  class MsDtypLuid < BinData::Record
    endian :little

    uint32 :low_part
    int32  :high_part

    def to_s
      "0x#{high_part.to_i.to_s(16)}#{low_part.to_i.to_s(16).rjust(8, '0')}"
    end
  end

  # [2.3.5 LARGE_INTEGER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/e904b1ba-f774-4203-ba1b-66485165ab1a)
  class MsDtypLargeInteger < BinData::Record
    endian :big_and_little

    uint32 :low_part
    int32  :high_part

    def to_datetime
      RubySMB::Field::FileTime.new(to_i).to_datetime
    end

    def to_i
      (high_part.to_i << 32) | low_part.to_i
    end
  end
end
