# -*- coding: binary -*-

module Rex::Proto::MsDtyp
  # [2.4.3 ACCESS_MASK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b)
  class MsDtypAccessMask < BinData::Record
    endian :little
    hide   :reserved0, :reserved1

    # the protocol field id reserved for protocol-specific access rights
    bit16 :protocol

    bit3  :reserved0
    bit1  :sy
    bit1  :wo
    bit1  :wd
    bit1  :rc
    bit1  :de

    bit1  :gr
    bit1  :gw
    bit1  :gx
    bit1  :ga
    bit2  :reserved1
    bit1  :ma
    bit1  :as

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
      raise ArgumentError.new("Invalid SID: #{val}") unless val.is_a?(String) && val =~ /^S-1-(\d+)(-\d+)+$/

      _, _, ia, sa = val.split('-', 4)
      self.identifier_authority = [ia.to_i].pack('Q>')[2..].bytes
      self.sub_authority = sa.split('-').map(&:to_i)
    end

    def get
      str = 'S-1'
      str << "-#{("\x00\x00" + identifier_authority.to_binary_s).unpack1('Q>')}"
      str << '-' + sub_authority.map(&:to_s).join('-')
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
      bit1 :reserved
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

    uint32             :access_mask
    ms_dtyp_sid        :sid, byte_align: 4
  end

  class MsDtypAceObjectBody < BinData::Record
    endian :little

    uint32             :access_mask
    struct             :flags do
      bit1 :reserved5
      bit1 :reserved4
      bit1 :reserved3
      bit1 :reserved2
      bit1 :reserved1
      bit1 :reserved
      bit1 :ace_inherited_object_type_present
      bit1 :ace_object_type_present
    end
    ms_dtyp_guid       :object_type, onlyif: -> { flags.ace_object_type_present != 0x0 }
    ms_dtyp_guid       :inherited_object_type, onlyif: -> { flags.ace_inherited_object_type_present != 0x0 }
    ms_dtyp_sid        :sid, byte_align: 4
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
