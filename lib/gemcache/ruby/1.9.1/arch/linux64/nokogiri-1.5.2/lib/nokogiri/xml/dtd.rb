module Nokogiri
  module XML
    class DTD < Nokogiri::XML::Node
      undef_method :attribute_nodes
      undef_method :values
      undef_method :content
      undef_method :namespace
      undef_method :namespace_definitions
      undef_method :line if method_defined?(:line)

      def keys
        attributes.keys
      end

      def each &block
        attributes.each { |key, value|
          block.call([key, value])
        }
      end
    end
  end
end
