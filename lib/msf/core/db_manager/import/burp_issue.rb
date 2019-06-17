require 'rex/parser/burp_issue_nokogiri'

module Msf::DBManager::Import::BurpIssue
  def import_burp_issue_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:workspace] || args[:wspace]
    parser = "Nokogiri v#{::Nokogiri::VERSION}"
    noko_args = args.dup
    noko_args[:blacklist] = bl
    noko_args[:wspace] = wspace
    if block
      yield(:parser, parser)
      doc = Rex::Parser::BurpIssueDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::BurpIssueDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end
end
