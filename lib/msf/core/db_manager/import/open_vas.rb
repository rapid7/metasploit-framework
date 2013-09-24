module Msf::DBManager::Import::OpenVAS
  #
  # Of course they had to change the nessus format.
  #
  def import_openvas_xml(args={}, &block)
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    raise DBImportError.new("No OpenVAS XML support. Please submit a patch to msfdev[at]metasploit.com")
  end

  def import_openvas_new_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_wapiti_xml(args.merge(:data => data))
  end

  def import_openvas_new_xml(args={}, &block)
    if block
      doc = Rex::Parser::OpenVASDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::OpenVASDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end
end