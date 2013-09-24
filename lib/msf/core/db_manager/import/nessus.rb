module Msf::DBManager::Import::Nessus
  #
  # This holds all of the shared parsing/handling used by the
  # Nessus NBE and NESSUS v1 methods
  #
  def handle_nessus(wspace, hobj, port, nasl, plugin_name, severity, data,task=nil)
    addr = hobj.address
    # The port section looks like:
    #   http (80/tcp)
    p = port.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)
    return if not p

    # Unnecessary as the caller should already have reported this host
    #report_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive)
    name = p[1].strip
    port = p[2].to_i
    proto = p[3].downcase

    info = { :workspace => wspace, :host => hobj, :port => port, :proto => proto, :task => task }
    if name != "unknown" and name[-1,1] != "?"
      info[:name] = name
    end
    report_service(info)

    if nasl.nil? || nasl.empty? || nasl == 0 || nasl == "0"
      return
    end

    data.gsub!("\\n", "\n")

    refs = []

    if (data =~ /^CVE : (.*)$/)
      $1.gsub(/C(VE|AN)\-/, '').split(',').map { |r| r.strip }.each do |r|
        refs.push('CVE-' + r)
      end
    end

    if (data =~ /^BID : (.*)$/)
      $1.split(',').map { |r| r.strip }.each do |r|
        refs.push('BID-' + r)
      end
    end

    if (data =~ /^Other references : (.*)$/)
      $1.split(',').map { |r| r.strip }.each do |r|
        ref_id, ref_val = r.split(':')
        ref_val ? refs.push(ref_id + '-' + ref_val) : refs.push(ref_id)
      end
    end

    nss = 'NSS-' + nasl.to_s.strip
    refs << nss

    unless plugin_name.to_s.strip.empty?
      vuln_name = plugin_name
    else
      vuln_name = nss
    end

    vuln_info = {
        :workspace => wspace,
        :host => hobj,
        :port => port,
        :proto => proto,
        :name => vuln_name,
        :info => data,
        :refs => refs,
        :task => task,
    }
    report_vuln(vuln_info)
  end

  #
  # NESSUS v2 file format has a dramatically different layout
  # for ReportItem data
  #
  def handle_nessus_v2(wspace,hobj,port,proto,name,nasl,nasl_name,severity,description,cve,bid,xref,msf,task=nil)
    addr = hobj.address

    info = { :workspace => wspace, :host => hobj, :port => port, :proto => proto, :task => task }

    unless name =~ /^unknown$|\?$/
      info[:name] = name
    end

    if port.to_i != 0
      report_service(info)
    end

    if nasl.nil? || nasl.empty? || nasl == 0 || nasl == "0"
      return
    end

    refs = []

    cve.each do |r|
      r.to_s.gsub!(/C(VE|AN)\-/, '')
      refs.push('CVE-' + r.to_s)
    end if cve

    bid.each do |r|
      refs.push('BID-' + r.to_s)
    end if bid

    xref.each do |r|
      ref_id, ref_val = r.to_s.split(':')
      ref_val ? refs.push(ref_id + '-' + ref_val) : refs.push(ref_id)
    end if xref

    msfref = "MSF-" << msf if msf
    refs.push msfref if msfref

    nss = 'NSS-' + nasl
    if nasl_name.nil? || nasl_name.empty?
      vuln_name = nss
    else
      vuln_name = nasl_name
    end

    refs << nss.strip

    vuln = {
        :workspace => wspace,
        :host => hobj,
        :name => vuln_name,
        :info => description ? description : "",
        :refs => refs,
        :task => task,
    }

    if port.to_i != 0
      vuln[:port]  = port
      vuln[:proto] = proto
    end

    report_vuln(vuln)
  end

  #
  # Import Nessus XML v1 and v2 output
  #
  # Old versions of openvas exported this as well
  #
  def import_nessus_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end

    if data.index("NessusClientData_v2")
      import_nessus_xml_v2(args.merge(:data => data))
    else
      import_nessus_xml(args.merge(:data => data))
    end
  end

  def import_nessus_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    doc = rexmlify(data)
    doc.elements.each('/NessusClientData/Report/ReportHost') do |host|
      hobj = nil
      addr = nil
      hname = nil
      os = nil
      # If the name is resolved, the Nessus plugin for DNS
      # resolution should be there. If not, fall back to the
      # HostName
      host.elements.each('ReportItem') do |item|
        next unless item.elements['pluginID'].text == "12053"
        addr = item.elements['data'].text.match(/([0-9\x2e]+) resolves as/)[1]
        hname = host.elements['HostName'].text
      end
      addr ||= host.elements['HostName'].text
      next unless ipv46_validator(addr) # Skip resolved names and SCAN-ERROR.
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      hinfo = {
          :workspace => wspace,
          :host => addr,
          :task => args[:task]
      }

      # Record the hostname
      hinfo.merge!(:name => hname.to_s.strip) if hname
      hobj = report_host(hinfo)
      report_import_note(wspace,hobj)

      # Record the OS
      os ||= host.elements["os_name"]
      if os
        report_note(
            :workspace => wspace,
            :task => args[:task],
            :host => hobj,
            :type => 'host.os.nessus_fingerprint',
            :data => {
                :os => os.text.to_s.strip
            }
        )
      end

      host.elements.each('ReportItem') do |item|
        nasl = item.elements['pluginID'].text
        plugin_name = item.elements['pluginName'].text
        port = item.elements['port'].text
        data = item.elements['data'].text
        severity = item.elements['severity'].text

        handle_nessus(wspace, hobj, port, nasl, plugin_name, severity, data, args[:task])
      end
    end
  end

  def import_nessus_xml_v2(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    #@host = {
    #'hname'             => nil,
    #'addr'              => nil,
    #'mac'               => nil,
    #'os'                => nil,
    #'ports'             => [ 'port' => {    'port'              	=> nil,
    #					'svc_name'              => nil,
    #					'proto'              	=> nil,
    #					'severity'              => nil,
    #					'nasl'              	=> nil,
    #					'description'           => nil,
    #					'cve'                   => [],
    #					'bid'                   => [],
    #					'xref'                  => []
    #				}
    #			]
    #}
    parser = Rex::Parser::NessusXMLStreamParser.new
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

      host_info = {
          :workspace => wspace,
          :host => addr,
          :task => args[:task]
      }
      host_info[:name] = hname.to_s.strip if hname
      # Short mac, protect against Nessus's habit of saving multiple macs
      # We can't use them anyway, so take just the first.
      host_info[:mac]  = mac.to_s.strip.upcase.split(/\s+/).first if mac

      hobj = report_host(host_info)
      report_import_note(wspace,hobj)

      os = host['os']
      yield(:os,os) if block
      if os
        report_note(
            :workspace => wspace,
            :task => args[:task],
            :host => hobj,
            :type => 'host.os.nessus_fingerprint',
            :data => {
                :os => os.to_s.strip
            }
        )
      end

      host['ports'].each do |item|
        next if item['port'] == 0
        msf = nil
        nasl = item['nasl'].to_s
        nasl_name = item['nasl_name'].to_s
        port = item['port'].to_s
        proto = item['proto'] || "tcp"
        sname = item['svc_name']
        severity = item['severity']
        description = item['description']
        cve = item['cve']
        bid = item['bid']
        xref = item['xref']
        msf = item['msf']

        yield(:port,port) if block

        handle_nessus_v2(wspace, hobj, port, proto, sname, nasl, nasl_name, severity, description, cve, bid, xref, msf, args[:task])

      end
      yield(:end,hname) if block
    }

    REXML::Document.parse_stream(data, parser)

  end

  #
  # Import Nessus NBE files
  #
  def import_nessus_nbe_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nessus_nbe(args.merge(:data => data))
  end

  # There is no place the NBE actually stores the plugin name used to
  # scan. You get "Security Note" or "Security Warning," and that's it.
  def import_nessus_nbe(args={}, &block)
    nbe_data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    nbe_copy = nbe_data.dup
    # First pass, just to build the address map.
    addr_map = {}

    # Cache host objects before passing into handle_nessus()
    hobj_map = {}

    nbe_copy.each_line do |line|
      r = line.split('|')
      next if r[0] != 'results'
      next if r[4] != "12053"
      data = r[6]
      addr,hname = data.match(/([0-9\x2e]+) resolves as (.+)\x2e\\n/)[1,2]
      addr_map[hname] = addr
    end

    nbe_data.each_line do |line|
      r = line.split('|')
      next if r[0] != 'results'
      hname = r[2]
      if addr_map[hname]
        addr = addr_map[hname]
      else
        addr = hname # Must be unresolved, probably an IP address.
      end
      port = r[3]
      nasl = r[4]
      type = r[5]
      data = r[6]

      # If there's no resolution, or if it's malformed, skip it.
      next unless ipv46_validator(addr)

      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      hobj_map[ addr ] ||= report_host(:host => addr, :workspace => wspace, :task => args[:task])

      # Match the NBE types with the XML severity ratings
      case type
        # log messages don't actually have any data, they are just
        # complaints about not being able to perform this or that test
        # because such-and-such was missing
        when "Log Message"; next
        when "Security Hole"; severity = 3
        when "Security Warning"; severity = 2
        when "Security Note"; severity = 1
        # a severity 0 means there's no extra data, it's just an open port
        else; severity = 0
      end
      if nasl == "11936"
        os = data.match(/The remote host is running (.*)\\n/)[1]
        report_note(
            :workspace => wspace,
            :task => args[:task],
            :host => hobj_map[ addr ],
            :type => 'host.os.nessus_fingerprint',
            :data => {
                :os => os.to_s.strip
            }
        )
      end

      next if nasl.to_s.strip.empty?
      plugin_name = nil # NBE doesn't ever populate this
      handle_nessus(wspace, hobj_map[ addr ], port, nasl, plugin_name, severity, data)
    end
  end
end