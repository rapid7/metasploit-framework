require "rex/parser/nokogiri_doc_mixin"

module Rex
  module Parser

    load_nokoigiri && class WapitiDocument < Nokogiri::XML::SAX::Document

    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block
      @state[:current_tag][name] = true

      case name
      when "report"
      when "generateBy"
      when "bugTypeList"
      when "bugType"
      when "bug"
      when "timestamp"
        @state[:has_text] = true
      when "url"
        @state[:has_text] = true
      when "peer"
      when "addr"
        @state[:has_text] = true
      when "port"
        @state[:has_text] = true
      when "parameter"
        @state[:has_text] = true
      when "info"
        @state[:has_text] = true
      when "description"
        @state[:has_text] = true
      when "solution"
        @state[:has_text] = true
      when "references"
      when "reference"
      when "title"
        @state[:has_text] = true
      end
    end

    def end_element(name=nil)
      block = @block
      case name
      when "timestamp"
        @state[:timestamp] = @text.strip
        @text = nil
      when "url"
        @state[:url] = @text.strip
        @text = nil
      when "addr"
        @state[:host] = @text.strip
        @text = nil
      when "port"
        @state[:port] = @text.strip
        @text = nil
      when "parameter"
        @state[:parameter] = @text.strip
        @text = nil
      when "info"
        @state[:info] = @text.strip
        @text = nil
      when "bug"
        report_vuln
      end
    end

    def report_vuln

    end
  end
end
