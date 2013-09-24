module Msf::DBManager::Import::Nmap
  #
  # Import Nmap's -oX xml output
  #
  def import_nmap_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nmap_xml(args.merge(:data => data))
  end

  def import_nmap_noko_stream(args, &block)
    if block
      doc = Rex::Parser::NmapDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::NmapDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  # If you have Nokogiri installed, you'll be shunted over to
  # that. Otherwise, you'll hit the old NmapXMLStreamParser.
  def import_nmap_xml(args={}, &block)
    return nil if args[:data].nil? or args[:data].empty?
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    if Rex::Parser.nokogiri_loaded
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, "Nokogiri v#{::Nokogiri::VERSION}")
        import_nmap_noko_stream(noko_args) {|type, data| yield type,data }
      else
        import_nmap_noko_stream(noko_args)
      end
      return true
    end

    # XXX: Legacy nmap xml parser starts here.

    fix_services = args[:fix_services]
    data = args[:data]

    # Use a stream parser instead of a tree parser so we can deal with
    # huge results files without running out of memory.
    parser = Rex::Parser::NmapXMLStreamParser.new
    yield(:parser, parser.class.name) if block

    # Whenever the parser pulls a host out of the nmap results, store
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
      if (h["addrs"].has_key?("mac"))
        data[:mac] = h["addrs"]["mac"]
      end
      data[:state] = (h["status"] == "up") ? Msf::HostState::Alive : Msf::HostState::Dead
      data[:task] = args[:task]

      if ( h["reverse_dns"] )
        data[:name] = h["reverse_dns"]
      end

      # Only report alive hosts with ports to speak of.
      if(data[:state] != Msf::HostState::Dead)
        if h["ports"].size > 0
          if fix_services
            port_states = h["ports"].map {|p| p["state"]}.reject {|p| p == "filtered"}
            next if port_states.compact.empty?
          end
          yield(:address,data[:host]) if block
          hobj = report_host(data)
          report_import_note(wspace,hobj)
        end
      end

      if( h["os_vendor"] )
        note = {
            :workspace => wspace,
            :host => hobj || addr,
            :type => 'host.os.nmap_fingerprint',
            :task => args[:task],
            :data => {
                :os_vendor   => h["os_vendor"],
                :os_family   => h["os_family"],
                :os_version  => h["os_version"],
                :os_accuracy => h["os_accuracy"]
            }
        }

        if(h["os_match"])
          note[:data][:os_match] = h['os_match']
        end

        report_note(note)
      end

      if (h["last_boot"])
        report_note(
            :workspace => wspace,
            :host => hobj || addr,
            :type => 'host.last_boot',
            :task => args[:task],
            :data => {
                :time => h["last_boot"]
            }
        )
      end

      if (h["trace"])
        hops = []
        h["trace"]["hops"].each do |hop|
          hops << {
              "ttl"     => hop["ttl"].to_i,
              "address" => hop["ipaddr"].to_s,
              "rtt"     => hop["rtt"].to_f,
              "name"    => hop["host"].to_s
          }
        end
        report_note(
            :workspace => wspace,
            :host => hobj || addr,
            :type => 'host.nmap.traceroute',
            :task => args[:task],
            :data => {
                'port'  => h["trace"]["port"].to_i,
                'proto' => h["trace"]["proto"].to_s,
                'hops'  => hops
            }
        )
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
        extra = ""
        extra << p["product"]   + " " if p["product"]
        extra << p["version"]   + " " if p["version"]
        extra << p["extrainfo"] + " " if p["extrainfo"]

        data = {}
        data[:workspace] = wspace
        if fix_services
          data[:proto] = nmap_msf_service_map(p["protocol"])
        else
          data[:proto] = p["protocol"].downcase
        end
        data[:port]  = p["portid"].to_i
        data[:state] = p["state"]
        data[:host]  = hobj || addr
        data[:info]  = extra if not extra.empty?
        data[:task]  = args[:task]
        if p["name"] != "unknown"
          data[:name] = p["name"]
        end
        report_service(data)
      }
      #Parse the scripts output
      if h["scripts"]
        h["scripts"].each do |key,val|
          if key == "smb-check-vulns"
            if val =~ /MS08-067: VULNERABLE/
              vuln_info = {
                  :workspace => wspace,
                  :task => args[:task],
                  :host =>  hobj || addr,
                  :port => 445,
                  :proto => 'tcp',
                  :name => 'MS08-067',
                  :info => 'Microsoft Windows Server Service Crafted RPC Request Handling Unspecified Remote Code Execution',
                  :refs =>['CVE-2008-4250',
                           'BID-31874',
                           'OSVDB-49243',
                           'CWE-94',
                           'MSFT-MS08-067',
                           'MSF-Microsoft Server Service Relative Path Stack Corruption',
                           'NSS-34476']
              }
              report_vuln(vuln_info)
            end
            if val =~ /MS06-025: VULNERABLE/
              vuln_info = {
                  :workspace => wspace,
                  :task => args[:task],
                  :host =>  hobj || addr,
                  :port => 445,
                  :proto => 'tcp',
                  :name => 'MS06-025',
                  :info => 'Vulnerability in Routing and Remote Access Could Allow Remote Code Execution',
                  :refs =>['CVE-2006-2370',
                           'CVE-2006-2371',
                           'BID-18325',
                           'BID-18358',
                           'BID-18424',
                           'OSVDB-26436',
                           'OSVDB-26437',
                           'MSFT-MS06-025',
                           'MSF-Microsoft RRAS Service RASMAN Registry Overflow',
                           'NSS-21689']
              }
              report_vuln(vuln_info)
            end
            # This one has NOT been  Tested , remove this comment if confirmed working
            if val =~ /MS07-029: VULNERABLE/
              vuln_info = {
                  :workspace => wspace,
                  :task => args[:task],
                  :host =>  hobj || addr,
                  :port => 445,
                  :proto => 'tcp',
                  :name => 'MS07-029',
                  :info => 'Vulnerability in Windows DNS RPC Interface Could Allow Remote Code Execution',
                  # Add more refs based on nessus/nexpose .. results
                  :refs =>['CVE-2007-1748',
                           'OSVDB-34100',
                           'MSF-Microsoft DNS RPC Service extractQuotedChar()',
                           'NSS-25168']
              }
              report_vuln(vuln_info)
            end
          end
        end
      end
    }

    # XXX: Legacy nmap xml parser ends here.

    REXML::Document.parse_stream(data, parser)
  end
end