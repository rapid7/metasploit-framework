# -*- coding: binary -*-

require 'bindata'
require 'ruby_smb'
require 'rex/proto/secauthz/well_known_sids'

module Rex::Proto::MsDtyp
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
    def bit_names
      names = []
      names << :GENERIC_READ if self.gr != 0
      names << :GENERIC_WRITE if self.gw != 0
      names << :GENERIC_EXECUTE if self.gx != 0
      names << :GENERIC_ALL if self.ga != 0
      names << :MAXIMUM_ALLOWED if self.ma != 0
      names << :ACCESS_SYSTEM_SECURITY if self.as != 0
      names << :SYNCHRONIZE if self.sy != 0
      names << :WRITE_OWNER if self.wo != 0
      names << :WRITE_DACL if self.wd != 0
      names << :READ_CONTROL if self.rc != 0
      names << :DELETE if self.de != 0
      names
    end

    ALL  = MsDtypAccessMask.new({ gr: 1, gw: 1, gx: 1, ga: 1, ma: 1, as: 1, sy: 1, wo: 1, wd: 1, rc: 1, de: 1, protocol: 0xffff })
    NONE = MsDtypAccessMask.new({ gr: 0, gw: 0, gx: 0, ga: 0, ma: 0, as: 0, sy: 0, wo: 0, wd: 0, rc: 0, de: 0, protocol: 0 })
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
      ace_header = parent&.header
      return 0 if ace_header.nil?
      ace_size = ace_header&.ace_size
      return 0 if ace_size.nil? or (ace_size == 0)

      ace_header_length = ace_header.to_binary_s.length
      body = parent&.body
      if body.nil?
        return 0 # Read no data as there is no body, so either we have done some data misalignment or we shouldn't be reading data.
      else
        ace_body_length = body.to_binary_s.length
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

    def self.from_sddl_text(sddl_text, domain_sid:)
      sacl_set = dacl_set = false
      sd = self.new
      sddl_text = sddl_text.dup.gsub(/\s/, '')  # start by removing all whitespace
      sddl_text.scan(/([OGDS]:(?:.(?!:))*)/).each do |part,|
        component, _, value = part.partition(':')
        case component
        when 'O'
          if sd.owner_sid.present?
            raise RuntimeError.new('SDDL parse error on extra owner SID')
          end

          sd.owner_sid = self.parse_sddl_sid(value, domain_sid: domain_sid)
        when 'G'
          if sd.group_sid.present?
            raise RuntimeError.new('SDDL parse error on extra group SID')
          end

          sd.group_sid = self.parse_sddl_sid(value, domain_sid: domain_sid)
        when 'D'
          raise RuntimeError.new('SDDL parse error on extra DACL') if dacl_set

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
              raise RuntimeError.new('SDDL parse error on unknown DACL flag: ' + flag)
            end
          end

          next unless access_control

          sd.dacl = MsDtypAcl.new
          sd.dacl.aces = self.parse_sddl_aces(value.delete_prefix(flags), domain_sid: domain_sid)
        when 'S'
          raise RuntimeError.new('SDDL parse error on extra SACL') if sacl_set

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
              raise RuntimeError.new('SDDL parse error on unknown SACL flag: ' + flag)
            end
          end

          next unless access_control

          sd.sacl = MsDtypAcl.new
          sd.sacl.aces = self.parse_sddl_aces(value.delete_prefix(flags), domain_sid: domain_sid)
        else
          raise RuntimeError.new('SDDL parse error on unknown directive: ' + part[0])
        end
      end

      sd
    end

    class << self
      private

      def parse_sddl_ace(ace, domain_sid:)
        parts = ace.upcase.split(';', -1)
        raise RuntimeError.new('SDDL parse error on too few ACE fields') if parts.length < 6
        raise RuntimeError.new('SDDL parse error on too many ACE fields') if parts.length > 7

        ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = parts[0...6]
        resource_attribute = parts[6]

        ace = MsDtypAce.new
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
          raise RuntimeError.new('SDDL parse error on unsupported ACE type: ' + ace_type)
        else
          raise RuntimeError.new('SDDL parse error on unknown ACE type: ' + ace_type)
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
            raise RuntimeError.new('SDDL parse error on unsupported ACE flag: TP')
          when 'CR'
            ace.header.ace_flags.critical_ace_flag = true
          when ''
          else
            raise RuntimeError.new('SDDL parse error on unknown ACE flag: ' + flag)
          end
        end

        rights.split(/(G[ARWX]|RC|SD|WD|WO|RP|WP|CC|DC|LC|SW|LO|DT|CR|F[ARWX]|K[ARWX]|N[RWX])/).each do |right|
          case right
          # generic access rights
          when 'GA', 'GR', 'GW', 'GX'
            ace.body.access_mask.send("#{right.downcase}=", true)
          # standard access rights
          when 'RC'
            ace.body.access_mask.rc = true
          when 'SD'
            ace.body.access_mask.de = true
          when 'WD', 'WO'
            ace.body.access_mask.send("#{right.downcase}=", true)
          # directory service object access rights
          when 'RP'
            ace.body.access_mask.protocol |= 16
          when 'WP'
            ace.body.access_mask.protocol |= 32
          when 'CC'
            ace.body.access_mask.protocol |= 1
          when 'DC'
            ace.body.access_mask.protocol |= 2
          when 'LC'
            ace.body.access_mask.protocol |= 4
          when 'SW'
            ace.body.access_mask.protocol |= 8
          when 'LO'
            ace.body.access_mask.protocol |= 128
          when 'DT'
            ace.body.access_mask.protocol |= 64
          when 'CR'
            ace.body.access_mask.protocol |= 256
          # file access rights
          when 'FA'
            ace.body.access_mask.protocol |= 0x1ff
            ace.body.access_mask.de = true
            ace.body.access_mask.rc = true
            ace.body.access_mask.wd = true
            ace.body.access_mask.wo = true
            ace.body.access_mask.sy = true
          when 'FR'
            ace.body.access_mask.protocol |= 0x89
          when 'FW'
            ace.body.access_mask.protocol |= 0x116
          when 'FX'
            ace.body.access_mask.protocol |= 0xa0
          # registry key access rights
          when 'KA'
            ace.body.access_mask.protocol |= 0x3f
            ace.body.access_mask.de = true
            ace.body.access_mask.rc = true
            ace.body.access_mask.wd = true
            ace.body.access_mask.wo = true
          when 'KR'
            ace.body.access_mask.protocol |= 0x19
          when 'KW'
            ace.body.access_mask.protocol |= 0x06
          when 'KX'
            ace.body.access_mask.protocol |= 0x19
          when 'NR', 'NW', 'NX'
            raise RuntimeError.new('SDDL parse error on unsupported ACE access right: ' + right)
          when ''
          else
            raise RuntimeError.new('SDDL parse error on unknown ACE access right: ' + right)
          end
        end

        unless object_guid.blank?
          begin
            guid = MsDtypGuid.new(object_guid)
          rescue StandardError
            raise RuntimeError.new('SDDL parse error on invalid object GUID: ' + object_guid)
          end

          unless ace.body.respond_to?('object_type=')
            raise RuntimeError.new('SDDL error on setting object type for incompatible ACE type')
          end
          ace.body.flags.ace_object_type_present = true
          ace.body.object_type = guid
        end

        unless inherit_object_guid.blank?
          begin
            guid = MsDtypGuid.new(inherit_object_guid)
          rescue StandardError
            raise RuntimeError.new('SDDL parse error on invalid object GUID: ' + inherit_object_guid)
          end

          unless ace.body.respond_to?('inherited_object_type=')
            raise RuntimeError.new('SDDL error on setting object type for incompatible ACE type')
          end
          ace.body.flags.ace_inherited_object_type_present = true
          ace.body.inherited_object_type = guid
        end

        unless account_sid.blank?
          ace.body.sid = self.parse_sddl_sid(account_sid, domain_sid: domain_sid)
        end

        unless resource_attribute.blank?
          raise RuntimeError.new('SDDL parse error on unsupported resource attribute: ' + resource_attribute)
        end

        ace
      end

      def parse_sddl_aces(aces, domain_sid:)
        ace_regex = /\([^\)]*\)/

        invalid_aces = aces.split(ace_regex).reject(&:empty?)
        unless invalid_aces.empty?
          raise RuntimeError.new('SDDL parse error on malformed ACE: ' + invalid_aces.first)
        end

        aces.scan(ace_regex).map do |ace_text|
          self.parse_sddl_ace(ace_text[1...-1], domain_sid: domain_sid)
        end
      end

      def parse_sddl_sid(sid, domain_sid:)
        # see: https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
        sid = sid.dup.upcase

        # these can be validated using powershell where ?? is the code
        #   (ConvertFrom-SddlString -Sddl "O:??").RawDescriptor.Owner
        case sid
        when 'AA'  # SDDL_ACCESS_CONTROL_ASSISTANCE_OPS
          sid = Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_ACCESS_CONTROL_ASSISTANCE_OPS
        when 'AC'  # SDDL_ALL_APP_PACKAGES
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_ALL_APP_PACKAGES
        when 'AN'  # SDDL_ANONYMOUS
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_ANONYMOUS_LOGON_SID
        when 'AO'  # SDDL_ACCOUNT_OPERATORS
          sid = Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_ACCOUNT_OPS
        when 'AP'  # SDDL_PROTECTED_USERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_PROTECTED_USERS}"
        when 'AU'  # SDDL_AUTHENTICATED_USERS
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATED_USER_SID
        when 'BA'  # SDDL_BUILTIN_ADMINISTRATORS
          sid = Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_ADMINS
        when 'BG'  # SDDL_BUILTIN_GUESTS
          sid = Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_GUESTS
        when 'BO'  # SDDL_BACKUP_OPERATORS
          sid = Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_BACKUP_OPS
        when 'BU'  # SDDL_BUILTIN_USERS
          sid = Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_SID_USERS
        when 'CA'  # SDDL_CERT_SERV_ADMINISTRATORS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_CERT_ADMINS}"
        when 'CD'  # SDDL_CERTSVC_DCOM_ACCESS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP}"
        when 'CG'  # SDDL_CREATOR_GROUP
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_CREATOR_GROUP_SID
        when 'CN'  # SDDL_CLONEABLE_CONTROLLERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_CLONEABLE_CONTROLLERS}"
        when 'CO'  # SDDL_CREATOR_OWNER
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_CREATOR_OWNER_SID
        when 'CY'  # SDDL_CRYPTO_OPERATORS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_CRYPTO_OPERATORS}"
        when 'DA'  # SDDL_DOMAIN_ADMINISTRATORS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ADMINS}"
        when 'DC'  # SDDL_DOMAIN_COMPUTERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_COMPUTERS}"
        when 'DD'  # SDDL_DOMAIN_DOMAIN_CONTROLLERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_CONTROLLERS}"
        when 'DG'  # SDDL_DOMAIN_GUESTS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_GUESTS}"
        when 'DU'  # SDDL_DOMAIN_USERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_USERS}"
        when 'EA'  # SDDL_ENTERPRISE_ADMINS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ENTERPRISE_ADMINS}"
        when 'ED'  # SDDL_ENTERPRISE_DOMAIN_CONTROLLERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_ENTERPRISE_CONTROLLERS_SID}"
        when 'EK'  # SDDL_ENTERPRISE_KEY_ADMINS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ENTERPRISE_KEY_ADMINS}"
        when 'ER'  # SDDL_EVENT_LOG_READERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_EVENT_LOG_READERS_GROUP}"
        when 'ES'  # SDDL_RDS_ENDPOINT_SERVERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_RDS_ENDPOINT_SERVERS}"
        when 'HA'  # SDDL_HYPER_V_ADMINS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_HYPER_V_ADMINS}"
        when 'HI'  # SDDL_ML_HIGH
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_HIGH_RID}"
        when 'IS'  # SDDL_IIS_USERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_IUSERS}"
        when 'IU'  # SDDL_INTERACTIVE
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_INTERACTIVE_SID
        when 'KA'  # SDDL_KEY_ADMINS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_KEY_ADMINS}"
        when 'LA'  # SDDL_LOCAL_ADMIN
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_USER_RID_ADMIN}"
        when 'LG'  # SDDL_LOCAL_GUEST
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_USER_RID_GUEST}"
        when 'LS'  # SDDL_LOCAL_SERVICE
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_LOCAL_SERVICE_SID
        when 'LU'  # SDDL_PERFLOG_USERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_LOGGING_USERS}"
        when 'LW'  # SDDL_ML_LOW
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_LOW_RID}"
        when 'ME'  # SDDL_ML_MEDIUM
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_MEDIUM_RID}"
        when 'MP'  # SDDL_ML_MEDIUM_PLUS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_MEDIUM_PLUS_RID}"
        when 'MU'  # SDDL_PERFMON_USERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_MONITORING_USERS}"
        when 'NO'  # SDDL_NETWORK_CONFIGURATION_OPS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS}"
        when 'NS'  # SDDL_NETWORK_SERVICE
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_NETWORK_SERVICE_SID
        when 'NU'  # SDDL_NETWORK
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_NETWORK_SID
        when 'OW'  # SDDL_OWNER_RIGHTS
          sid = "#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_CREATOR_SID_AUTHORITY}-4"
        when 'PA'  # SDDL_GROUP_POLICY_ADMINS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_POLICY_ADMINS}"
        when 'PO'  # SDDL_PRINTER_OPERATORS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_PRINT_OPS}"
        when 'PS'  # SDDL_PERSONAL_SELF
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_PRINCIPAL_SELF_SID
        when 'PU'  # SDDL_POWER_USERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_POWER_USERS}"
        when 'RA'  # SDDL_RDS_REMOTE_ACCESS_SERVERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_RDS_REMOTE_ACCESS_SERVERS}"
        when 'RC'  # SDDL_RESTRICTED_CODE
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_RESTRICTED_CODE_SID
        when 'RD'  # SDDL_REMOTE_DESKTOP
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS}"
        when 'RE'  # SDDL_REPLICATOR
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_REPLICATOR}"
        when 'RM'  # SDDL_RMS__SERVICE_OPERATORS
          sid = "#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_BUILTIN_DOMAIN_SID}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_REMOTE_MANAGEMENT_USERS}"
        when 'RO'  # SDDL_ENTERPRISE_RO_DCs
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS}"
        when 'RS'  # SDDL_RAS_SERVERS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_RAS_SERVERS}"
        when 'RU'  # SDDL_ALIAS_PREW2KCOMPACC
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_PREW2KCOMPACCESS}"
        when 'SA'  # SDDL_SCHEMA_ADMINISTRATORS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_GROUP_RID_SCHEMA_ADMINS}"
        when 'SI'  # SDDL_ML_SYSTEM
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_MANDATORY_SYSTEM_SID
        when 'SO'  # SDDL_SERVER_OPERATORS
          sid = "#{domain_sid}-#{Rex::Proto::Secauthz::WellKnownSids::DOMAIN_ALIAS_RID_SYSTEM_OPS}"
        when 'SS'  # SDDL_SERVICE_ASSERTED
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_AUTHENTICATION_SERVICE_ASSERTED_SID
        when 'SU'  # SDDL_SERVICE
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_SERVICE_SID
        when 'SY'  # SDDL_LOCAL_SYSTEM
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_LOCAL_SYSTEM_SID
        when 'UD'  # SDDL_USER_MODE_DRIVERS
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_USERMODEDRIVERHOST_ID_BASE_SID
        when 'WD'  # SDDL_EVERYONE
          sid = "#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_WORLD_SID_AUTHORITY}-#{Rex::Proto::Secauthz::WellKnownSids::SECURITY_WORLD_RID}"
        when 'WR'  # SDDL_WRITE_RESTRICTED_CODE
          sid = Rex::Proto::Secauthz::WellKnownSids::SECURITY_WRITE_RESTRICTED_CODE_SID
        when /^S(-\d+)+/
        else
          raise RuntimeError, 'SDDL parse error on invalid SID string: ' + sid
        end


        MsDtypSid.new(sid)
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
      @owner_sid = get_parameter(:owner_sid)
      @group_sid = get_parameter(:group_sid)
      @sacl = get_parameter(:sacl)
      @dacl = get_parameter(:dacl)
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

    attr_accessor :owner_sid, :group_sid, :sacl, :dacl

    private

    def build_buffer
      buf = ''
      buf << owner_sid.to_binary_s if owner_sid
      buf << group_sid.to_binary_s if group_sid
      buf << sacl.to_binary_s if sacl
      buf << dacl.to_binary_s if dacl
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
      %i[ owner_sid group_sid sacl dacl ].each do |cursor|
        break if cursor == field

        cursor = instance_variable_get("@#{cursor}")
        offset += cursor.num_bytes if cursor
      end

      offset
    end
  end
end
