require 'rex/parser/burp_session_nokogiri'

module Msf::DBManager::Import::BurpSession
  def import_burp_session_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::BurpSessionDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::BurpSessionDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_burp_session_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || args[:workspace]
    if Rex::Parser.nokogiri_loaded
      # Rex::Parser.reload("burp_session_nokogiri.rb")
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_burp_session_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_burp_session_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise Msf::DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end
end
