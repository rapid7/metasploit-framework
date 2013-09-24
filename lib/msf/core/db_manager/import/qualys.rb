module Msf::DBManager::Import::Qualys
  #
  # Qualys report parsing/handling
  #
  def handle_qualys(wspace, hobj, port, protocol, qid, severity, refs, name=nil, title=nil, task=nil)
    addr = hobj.address
    port = port.to_i if port

    info = { :workspace => wspace, :host => hobj, :port => port, :proto => protocol, :task => task }
    if name and name != 'unknown' and name != 'No registered hostname'
      info[:name] = name
    end

    if info[:host] && info[:port] && info[:proto]
      report_service(info)
    end

    fixed_refs = []
    if refs
      refs.each do |ref|
        case ref
          when /^MS[0-9]{2}-[0-9]{3}/
            fixed_refs << "MSB-#{ref}"
          else
            fixed_refs << ref
        end
      end
    end

    return if qid == 0
    title = 'QUALYS-' + qid if title.nil? or title.empty?
    if addr
      report_vuln(
          :workspace => wspace,
          :task => task,
          :host => hobj,
          :port => port,
          :proto => protocol,
          :name =>  title,
          :refs => fixed_refs
      )
    end
  end

  def find_qualys_asset_vuln_refs(doc)
    vuln_refs = {}
    doc.elements.each("/ASSET_DATA_REPORT/GLOSSARY/VULN_DETAILS_LIST/VULN_DETAILS") do |vuln|
      next unless vuln.elements['QID'] && vuln.elements['QID'].first
      qid = vuln.elements['QID'].first.to_s
      vuln_refs[qid] ||= []
      vuln.elements.each('CVE_ID_LIST/CVE_ID') do |ref|
        vuln_refs[qid].push('CVE-' + /C..-([0-9\-]{9})/.match(ref.elements['ID'].text.to_s)[1])
      end
      vuln.elements.each('BUGTRAQ_ID_LIST/BUGTRAQ_ID') do |ref|
        vuln_refs[qid].push('BID-' + ref.elements['ID'].text.to_s)
      end
    end
    return vuln_refs
  end

  # Pull out vulnerabilities that have at least one matching
  # ref -- many "vulns" are not vulns, just audit information.
  def find_qualys_asset_vulns(host,wspace,hobj,vuln_refs,&block)
    host.elements.each("VULN_INFO_LIST/VULN_INFO") do |vi|
      next unless vi.elements["QID"]
      vi.elements.each("QID") do |qid|
        next if vuln_refs[qid.text].nil? || vuln_refs[qid.text].empty?
        handle_qualys(wspace, hobj, nil, nil, qid.text, nil, vuln_refs[qid.text], nil,nil, args[:task])
      end
    end
  end

  # Takes QID numbers and finds the discovered services in
  # a qualys_asset_xml.
  def find_qualys_asset_ports(i,host,wspace,hobj)
    return unless (i == 82023 || i == 82004)
    proto = i == 82023 ? 'tcp' : 'udp'
    qid = host.elements["VULN_INFO_LIST/VULN_INFO/QID[@id='qid_#{i}']"]
    qid_result = qid.parent.elements["RESULT[@format='table']"] if qid
    hports = qid_result.first.to_s if qid_result
    if hports
      hports.scan(/([0-9]+)\t(.*?)\t.*?\t([^\t\n]*)/) do |match|
        if match[2] == nil or match[2].strip == 'unknown'
          name = match[1].strip
        else
          name = match[2].strip
        end
        handle_qualys(wspace, hobj, match[0].to_s, proto, 0, nil, nil, name, nil, args[:task])
      end
    end
  end

  #
  # Import Qualys's Asset Data Report format
  #
  def import_qualys_asset_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    doc = rexmlify(data)
    vuln_refs = find_qualys_asset_vuln_refs(doc)

    # 2nd pass, actually grab the hosts.
    doc.elements.each("/ASSET_DATA_REPORT/HOST_LIST/HOST") do |host|
      hobj = nil
      addr = host.elements["IP"].text if host.elements["IP"]
      next unless validate_ips(addr)
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end
      hname = ( # Prefer NetBIOS over DNS
      (host.elements["NETBIOS"].text if host.elements["NETBIOS"]) ||
          (host.elements["DNS"].text if host.elements["DNS"]) ||
          "" )
      hobj = report_host(:workspace => wspace, :host => addr, :name => hname, :state => Msf::HostState::Alive, :task => args[:task])
      report_import_note(wspace,hobj)

      if host.elements["OPERATING_SYSTEM"]
        hos = host.elements["OPERATING_SYSTEM"].text
        report_note(
            :workspace => wspace,
            :task => args[:task],
            :host => hobj,
            :type => 'host.os.qualys_fingerprint',
            :data => { :os => hos }
        )
      end

      # Report open ports.
      find_qualys_asset_ports(82023,host,wspace,hobj) # TCP
      find_qualys_asset_ports(82004,host,wspace,hobj) # UDP

      # Report vulns
      find_qualys_asset_vulns(host,wspace,hobj,vuln_refs,&block)

    end # host

  end

  #
  # Import Qualys' Scan xml output
  #
  def import_qualys_scan_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_qualys_scan_xml(args.merge(:data => data))
  end

  def import_qualys_scan_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []


    doc = rexmlify(data)
    doc.elements.each('/SCAN/IP') do |host|
      hobj = nil
      addr  = host.attributes['value']
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end
      hname = host.attributes['name'] || ''

      hobj = report_host(:workspace => wspace, :host => addr, :name => hname, :state => Msf::HostState::Alive, :task => args[:task])
      report_import_note(wspace,hobj)

      if host.elements["OS"]
        hos = host.elements["OS"].text
        report_note(
            :workspace => wspace,
            :task => args[:task],
            :host => hobj,
            :type => 'host.os.qualys_fingerprint',
            :data => {
                :os => hos
            }
        )
      end

      # Open TCP Services List (Qualys ID 82023)
      services_tcp = host.elements["SERVICES/CAT/SERVICE[@number='82023']/RESULT"]
      if services_tcp
        services_tcp.text.scan(/([0-9]+)\t(.*?)\t.*?\t([^\t\n]*)/) do |match|
          if match[2] == nil or match[2].strip == 'unknown'
            name = match[1].strip
          else
            name = match[2].strip
          end
          handle_qualys(wspace, hobj, match[0].to_s, 'tcp', 0, nil, nil, name, nil, args[:task])
        end
      end
      # Open UDP Services List (Qualys ID 82004)
      services_udp = host.elements["SERVICES/CAT/SERVICE[@number='82004']/RESULT"]
      if services_udp
        services_udp.text.scan(/([0-9]+)\t(.*?)\t.*?\t([^\t\n]*)/) do |match|
          if match[2] == nil or match[2].strip == 'unknown'
            name = match[1].strip
          else
            name = match[2].strip
          end
          handle_qualys(wspace, hobj, match[0].to_s, 'udp', 0, nil, nil, name, nil, args[:task])
        end
      end

      # VULNS are confirmed, PRACTICES are unconfirmed vulnerabilities
      host.elements.each('VULNS/CAT | PRACTICES/CAT') do |cat|
        port = cat.attributes['port']
        protocol = cat.attributes['protocol']
        cat.elements.each('VULN | PRACTICE') do |vuln|
          refs = []
          qid = vuln.attributes['number']
          severity = vuln.attributes['severity']
          title = vuln.elements['TITLE'].text.to_s
          vuln.elements.each('VENDOR_REFERENCE_LIST/VENDOR_REFERENCE') do |ref|
            refs.push(ref.elements['ID'].text.to_s)
          end
          vuln.elements.each('CVE_ID_LIST/CVE_ID') do |ref|
            refs.push('CVE-' + /C..-([0-9\-]{9})/.match(ref.elements['ID'].text.to_s)[1])
          end
          vuln.elements.each('BUGTRAQ_ID_LIST/BUGTRAQ_ID') do |ref|
            refs.push('BID-' + ref.elements['ID'].text.to_s)
          end

          handle_qualys(wspace, hobj, port, protocol, qid, severity, refs, nil,title, args[:task])
        end
      end
    end
  end
end