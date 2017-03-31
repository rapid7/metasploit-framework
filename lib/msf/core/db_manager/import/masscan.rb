require 'rex/parser/masscan_nokogiri'
require 'rex/parser/masscan_xml'

module Msf::DBManager::Import::Masscan
  def import_masscan_noko_stream(args, &block)
    if block
      doc = Rex::Parser::MasscanDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::MasscanDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  # If you have Nokogiri installed, you'll be shunted over to
  # that. Otherwise, you'll hit the old MasscanXMLStreamParser.
  def import_masscan_xml(args={}, &block)
    return nil if args[:data].nil? or args[:data].empty?
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    if Rex::Parser.nokogiri_loaded
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, "Nokogiri v#{::Nokogiri::VERSION}")
        import_masscan_noko_stream(noko_args) {|type, data| yield type,data }
      else
        import_masscan_noko_stream(noko_args)
      end
      return true
    end
    # XXX: Legacy masscan xml parser starts here.
    data = args[:data]
    # Use a stream parser instead of a tree parser so we can deal with
    # huge results files without running out of memory.
    parser = Rex::Parser::MasscanXMLStreamParser.new
    yield(:parser, parser.class.name) if block

    # Whenever the parser pulls a host out of the masscan results, store
    # it, along with any associated services, in the database.
    parser.on_found_host = Proc.new { |h|
      hobj = nil
      data = {:workspace => wspace}
      if (h["addrs"].has_key?("ipv4"))
        addr = h["addrs"]["ipv4"]
      elsif (h["addrs"].has_key?("ipv6"))
        addr = h["addrs"]["ipv6"]
      else
        # Can't report it if it doesn't have an IP
        raise RuntimeError, "At least one IPv4 or IPv6 address is required"
      end
      next if bl.include? addr
      data[:host] = addr
      # Masscan only reports hosts that are alive
      data[:state] = Msf::HostState::Alive
      #data[:task] = args[:task]
      # Only report alive hosts with ports to speak of.
      if(data[:state] != Msf::HostState::Dead)
        if h["ports"].size > 0
          yield(:address,data[:host]) if block
          hobj = report_host(data)
          report_import_note(wspace,hobj)
        end
      end

      # Put all the ports, regardless of state, into the db.
      h["ports"].each { |p|
        # Localhost port results are pretty unreliable -- if it's
        # unknown, it's no good (possibly Windows-only)
        if (
          p["state"] == "unknown" &&
          h["status_reason"] == "localhost-response"
        )
          next
        end

        data = {}
        data[:workspace] = wspace
        data[:port]  = p["portid"].to_i
        data[:state] = p["state"]
        data[:host]  = hobj || addr
        #data[:task]  = args[:task]
        report_service(data)
      }
    }

    # XXX: Legacy masscan xml parser ends here.

    REXML::Document.parse_stream(data, parser)
  end

  #
  # Import Masscan's -oX xml output
  #
  def import_masscan_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace
    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_masscan_xml(args.merge(:data => data))
  end

  def masscan_msf_service_map(proto)
    service_name_map(proto)
  end
end
