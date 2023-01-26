# frozen_string_literal: true

require 'bindata'
require 'ruby_smb/dcerpc'

# Temporarily adding this to framework instead of RubySMB
# Should be updated and moved there when implementing diamond tickets
# The problem with adding it to RubySMB now is if we update RubySMB structures afterwards,
# these changes will be backward non-compatible and this will require a major version bump
# (IDL/NDR) Pickles as defined in
# [(IDL/NDR) # Pickles](https://pubs.opengroup.org/onlinepubs/9668899/chap2.htm#tagcjh_05_01_07)
# and
# [2.2.6 Type Serialization Version # 1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/9a1d0f97-eac0-49ab-a197-f1a581c2d6a0)
module Rex::Proto::Kerberos::NDR
  # [2.2.6.1 Common Type Header for the Serialization Stream](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/6d75d40e-e2d2-4420-b9e9-8508a726a9ae)
  class TypeSerialization1CommonTypeHeader < BinData::Record
    default_parameter byte_align: 8
    endian :little

    uint8  :version, initial_value: 1
    uint8  :endianness, initial_value: 0x10
    uint16 :common_header_length, initial_value: 8
    uint32 :filler, initial_value: 0xCCCCCCCC
  end

  # [2.2.6.2 Private Header for Constructed Type](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/63949ba8-bc88-4c0c-9377-23f14b197827)
  class TypeSerialization1PrivateHeader < BinData::Record
    default_parameter byte_align: 8
    endian :little

    uint32 :object_buffer_length, initial_value: -> { parent.field_length(@obj.parent) }
    uint32 :filler, initial_value: 0x00000000
  end

  # [2.2.6 Type Serialization Version 1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/9a1d0f97-eac0-49ab-a197-f1a581c2d6a0)
  class TypeSerialization1 < BinData::Record
    PRIVATE_HEADER_BASE_NAME = 'private_header'

    default_parameter byte_align: 8
    endian :little
    search_prefix :type_serialization1

    common_type_header :common_header

    def field_length(obj)
      length = 0
      index = find_index_of(obj)
      if index
        each_pair { |n, o| length = o.num_bytes if n == field_names[index + 1] }
      end
      length
    end

    def self.method_missing(symbol, *args, &block)
      return super if dsl_parser.respond_to?(symbol)

      klass = BinData::RegisteredClasses.lookup(symbol, { endian: dsl_parser.endian, search_prefix: dsl_parser.search_prefix })
      if klass.new.is_a?(RubySMB::Dcerpc::Ndr::ConstructedTypePlugin)
        names = dsl_parser.fields.find_all do |field|
          field.prototype.instance_variable_get(:@obj_class) == TypeSerialization1PrivateHeader
        end.map(&:name).sort
        if names.empty?
          new_name = "#{PRIVATE_HEADER_BASE_NAME}1"
        else
          num = names.last.match(/#{PRIVATE_HEADER_BASE_NAME}(\d)$/)[1].to_i
          new_name = "#{PRIVATE_HEADER_BASE_NAME}#{num + 1}"
        end

        super(:private_header, new_name.to_sym)
      end

      super
    end
  end
end
