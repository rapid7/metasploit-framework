module Msf
module Util
module DotNetDeserialization
module Types

  class Record < BinData::Record; end  # forward definition

  require 'msf/util/dot_net_deserialization/types/primitives'
  require 'msf/util/dot_net_deserialization/types/general'
  require 'msf/util/dot_net_deserialization/types/record_values'

  #
  # .NET Serialization Types (Compound-Records)
  #
  class Record < BinData::Record
    endian                 :little
    uint8                  :record_type
    choice                 :record_value, selection: -> { record_type } do
      serialization_header_record             Enums::RecordTypeEnum[:SerializedStreamHeader]
      class_with_id                           Enums::RecordTypeEnum[:ClassWithId]
      system_class_with_members               Enums::RecordTypeEnum[:SystemClassWithMembers]
      #class_with_members                      Enums::RecordTypeEnum[:ClassWithMembers]
      system_class_with_members_and_types     Enums::RecordTypeEnum[:SystemClassWithMembersAndTypes]
      class_with_members_and_types            Enums::RecordTypeEnum[:ClassWithMembersAndTypes]
      binary_object_string                    Enums::RecordTypeEnum[:BinaryObjectString]
      #binary_array                            Enums::RecordTypeEnum[:BinaryArray]
      #member_primitive_typed                  Enums::RecordTypeEnum[:MemberPrimitiveTyped]
      member_reference                        Enums::RecordTypeEnum[:MemberReference]
      object_null                             Enums::RecordTypeEnum[:ObjectNull]
      message_end                             Enums::RecordTypeEnum[:MessageEnd]
      binary_library                          Enums::RecordTypeEnum[:BinaryLibrary]
      #object_null_multiple_256                Enums::RecordTypeEnum[:ObjectNullMultiple256]
      #object_null_multiple                    Enums::RecordTypeEnum[:ObjectNullMultiple]
      #array_single_primitive                  Enums::RecordTypeEnum[:ArraySinglePrimitive]
      #array_single_object                     Enums::RecordTypeEnum[:ArraySingleObject]
      array_single_string                     Enums::RecordTypeEnum[:ArraySingleString]
      #method_call                             Enums::RecordTypeEnum[:MethodCall]
      #method_return                           Enums::RecordTypeEnum[:MethodReturn]
    end

    def self.from_value(record_value, parent: nil)
      raise ::ArgumentError, 'Parameter record_value is invalid' unless record_value.class.const_defined?('RECORD_TYPE')

      args = [{record_type: record_value.class::RECORD_TYPE, record_value: record_value}]
      unless parent.nil?
        args << {}       # params
        args <<  parent  # parent object
      end
      self.new(*args)
    end
  end

  class RecordArray < BinData::Array
    default_parameters  type: :record

    # Allow reading records until either EoF or the last record type is MessageEnd
    module ReadRecordsUntilPlugin
      def do_read(io)
        loop do
          element = append_new_element
          begin
            element.do_read(io)
          rescue EOFError, IOError
            elements.pop
            break
          end

          break if elements[-1].record_type == Enums::RecordTypeEnum[:MessageEnd]
        end
      end
    end

    def initialize_shared_instance
      super

      extend ReadRecordsUntilPlugin
    end
  end

  class SerializedStream < BinData::Record
    endian                 :little
    record_array           :records

    def self.from_values(values)
      stream = self.new
      values.each do |contents|
        stream.records << Record.from_value(contents, parent: stream.records)
      end
      stream
    end

    def get_object(id)
      id = id.value if id.is_a? BinData::BasePrimitive

      @objects ||= {}
      @objects[id]
    end

    def set_object(id, object)
      id = id.value if id.is_a? BinData::BasePrimitive

      @objects ||= {}
      @objects[id] = object
    end
  end

end
end
end
end
