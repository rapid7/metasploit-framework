module Nokogiri
  module HTML
    module SAX
      class PushParser
        def initialize(doc = XML::SAX::Document.new, file_name = nil, encoding = 'UTF-8')
          @document = doc
          @encoding = encoding
          @sax_parser = HTML::SAX::Parser.new(doc, @encoding)

          ## Create our push parser context
          initialize_native(@sax_parser, file_name, @encoding)
        end
      end
    end
  end
end
