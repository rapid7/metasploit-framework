require 'tilt/template'

module Tilt
  # Nokogiri template implementation. See:
  # http://nokogiri.org/
  class NokogiriTemplate < Template
    self.default_mime_type = 'text/xml'

    def self.engine_initialized?
      defined? ::Nokogiri
    end

    def initialize_engine
      require_template_library 'nokogiri'
    end

    def prepare; end

    def evaluate(scope, locals, &block)
      block &&= proc { yield.gsub(/^<\?xml version=\"1\.0\"\?>\n?/, "") }

      if data.respond_to?(:to_str)
        super(scope, locals, &block)
      else
        ::Nokogiri::XML::Builder.new.tap(&data).to_xml
      end
    end

    def precompiled_preamble(locals)
      return super if locals.include? :xml
      "xml = ::Nokogiri::XML::Builder.new { |xml| }\n#{super}"
    end

    def precompiled_postamble(locals)
      "xml.to_xml"
    end

    def precompiled_template(locals)
      data.to_str
    end
  end
end

