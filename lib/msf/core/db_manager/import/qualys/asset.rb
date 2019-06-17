module Msf::DBManager::Import::Qualys::Asset
  # Takes QID numbers and finds the discovered services in
  # a qualys_asset_xml.
  def find_qualys_asset_ports(i,host,wspace,hobj,task_id)
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
        handle_qualys(wspace, hobj, match[0].to_s, proto, 0, nil, nil, name, nil, task_id)
      end
    end
  end

  def find_qualys_asset_vuln_refs(doc)
    vuln_refs = {}
    doc.elements.each("/ASSET_DATA_REPORT/GLOSSARY/VULN_DETAILS_LIST/VULN_DETAILS") do |vuln|
      next unless vuln.elements['QID'] && vuln.elements['QID'].first
      qid = vuln.elements['QID'].first.to_s
      vuln_refs[qid] ||= []
      vuln.elements.each('CVE_ID_LIST/CVE_ID') do |ref|
        vuln_refs[qid].push('CVE-' + /C..-([0-9\-]{9,})/.match(ref.elements['ID'].text.to_s)[1])
      end
      vuln.elements.each('BUGTRAQ_ID_LIST/BUGTRAQ_ID') do |ref|
        vuln_refs[qid].push('BID-' + ref.elements['ID'].text.to_s)
      end
    end
    return vuln_refs
  end

  # Pull out vulnerabilities that have at least one matching
  # ref -- many "vulns" are not vulns, just audit information.
  def find_qualys_asset_vulns(host,wspace,hobj,vuln_refs,task_id,&block)
    host.elements.each("VULN_INFO_LIST/VULN_INFO") do |vi|
      next unless vi.elements["QID"]
      vi.elements.each("QID") do |qid|
        next if vuln_refs[qid.text].nil? || vuln_refs[qid.text].empty?
        handle_qualys(wspace, hobj, nil, nil, qid.text, nil, vuln_refs[qid.text], nil, nil, task_id)
      end
    end
  end

  #
  # Import Qualys's Asset Data Report format
  #
  def import_qualys_asset_xml(args={}, &block)
    data = args[:data]
    wspace = args[:workspace] || args[:wspace]
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
      find_qualys_asset_ports(82023,host,wspace,hobj, args[:task]) # TCP
      find_qualys_asset_ports(82004,host,wspace,hobj, args[:task]) # UDP

      # Report vulns
      find_qualys_asset_vulns(host,wspace,hobj,vuln_refs, args[:task],&block)

    end # host

  end
end
