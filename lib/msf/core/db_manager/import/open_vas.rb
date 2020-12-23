require 'rex/parser/openvas_nokogiri'

module Msf::DBManager::Import::OpenVAS
  def import_openvas_noko_stream(args={}, &block)
    if block
      doc = Rex::Parser::OpenVASDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::OpenVASDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_openvas_new_xml(args={}, &block)
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:workspace] = wspace
      if block
        yield(:parser, parser)
        import_openvas_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_openvas_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise Msf::DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  #
  # Of course they had to change the nessus format.
  #
  def import_openvas_xml(args={}, &block)
    raise Msf::DBImportError.new("No OpenVas XML support. Please submit a patch to msfdev[at]metasploit.com")
  end
end
