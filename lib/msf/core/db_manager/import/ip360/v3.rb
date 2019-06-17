require 'rex/parser/ip360_xml'

module Msf::DBManager::Import::IP360::V3
  #
  # Import IP360 XML v3 output
  #
  def import_ip360_xml_file(args={})
    filename = args[:filename]

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_ip360_xml_v3(args.merge(:data => data))
  end

  #
  # Import IP360's xml output
  #
  def import_ip360_xml_v3(args={}, &block)
    data = args[:data]
    wspace = args[:workspace] || args[:wspace]
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    # @aspl = {'vulns' => {'name' => { }, 'cve' => { }, 'bid' => { } }
    # 'oses' => {'name' } }

    aspl_path  = nil
    aspl_paths = [
      ::File.join(Msf::Config.config_directory, "data", "ncircle", "ip360.aspl"),
      ::File.join(Msf::Config.data_directory, "ncircle", "ip360.aspl")
    ]

    aspl_paths.each do |tpath|
      next if not (::File.exist?(tpath) and ::File.readable?(tpath))
      aspl_path = tpath
      break
    end

    if not aspl_path
      raise Msf::DBImportError.new("The nCircle IP360 ASPL file is not present.\n    Download ASPL from nCircle VNE | Administer | Support | Resources, unzip it, and import it first")
    end

    # parse nCircle ASPL file
    aspl = ""
    ::File.open(aspl_path, "rb") do |f|
      aspl = f.read(f.stat.size)
    end

    @asplhash = nil
    parser = Rex::Parser::IP360ASPLXMLStreamParser.new
    parser.on_found_aspl = Proc.new { |asplh|
      @asplhash = asplh
    }
    REXML::Document.parse_stream(aspl, parser)

    # nCircle has some quotes escaped which causes the parser to break
    # we don't need these lines so just replace \" with "
    data.gsub!(/\\"/,'"')

    # parse nCircle Scan Output
    parser = Rex::Parser::IP360XMLStreamParser.new
    parser.on_found_host = Proc.new { |host|
      hobj = nil
      addr = host['addr'] || host['hname']

      next unless ipv46_validator(addr) # Catches SCAN-ERROR, among others.

      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      os = host['os']
      hname = host['hname']
      mac = host['mac']

      host_hash = {
        :workspace => wspace,
        :host => addr,
        :task => args[:task]
      }
      host_hash[:name] = hname.to_s.strip if hname
      host_hash[:mac]  = mac.to_s.strip.upcase if mac

      hobj = report_host(host_hash)

      yield(:os, os) if block
      if os
        report_note(
          :workspace => wspace,
          :task => args[:task],
          :host => hobj,
          :type => 'host.os.ip360_fingerprint',
          :data => {
            :os => @asplhash['oses'][os].to_s.strip
          }
        )
      end

      host['apps'].each do |item|
        port = item['port'].to_s
        proto = item['proto'].to_s

        handle_ip360_v3_svc(wspace, hobj, port, proto, hname, args[:task])
      end


      host['vulns'].each do |item|
        vulnid = item['vulnid'].to_s
        port = item['port'].to_s
        proto = item['proto'] || "tcp"
        vulnname = @asplhash['vulns']['name'][vulnid]
        cves = @asplhash['vulns']['cve'][vulnid]
        bids = @asplhash['vulns']['bid'][vulnid]

        yield(:port, port) if block

        handle_ip360_v3_vuln(wspace, hobj, port, proto, hname, vulnid, vulnname, cves, bids, args[:task])

      end

      yield(:end, hname) if block
    }

    REXML::Document.parse_stream(data, parser)
  end

  protected

  # IP360 v3 svc
  def handle_ip360_v3_svc(wspace,hobj,port,proto,hname,task=nil)
    addr = hobj.address
    report_host(:workspace => wspace, :host => hobj, :state => Msf::HostState::Alive, :task => task)

    info = { :workspace => wspace, :host => hobj, :port => port, :proto => proto, :task => task }
    if hname != "unknown" and hname[-1,1] != "?"
      info[:name] = hname
    end

    if port.to_i != 0
      report_service(info)
    end
  end

  #
  # IP360 v3 vuln
  #
  def handle_ip360_v3_vuln(wspace,hobj,port,proto,hname,vulnid,vulnname,cves,bids,task=nil)
    info = { :workspace => wspace, :host => hobj, :port => port, :proto => proto, :task => task }
    if hname != "unknown" and hname[-1,1] != "?"
      info[:name] = hname
    end

    if port.to_i != 0
      report_service(info)
    end

    refs = []

    cves.split(/,/).each do |cve|
      refs.push(cve.to_s)
    end if cves

    bids.split(/,/).each do |bid|
      refs.push('BID-' + bid.to_s)
    end if bids

    description = nil   # not working yet
    vuln = {
      :workspace => wspace,
      :host => hobj,
      :name => vulnname,
      :info => description ? description : "",
      :refs => refs,
      :task => task
    }

    if port.to_i != 0
      vuln[:port]  = port
      vuln[:proto] = proto
    end

    report_vuln(vuln)
  end
end
