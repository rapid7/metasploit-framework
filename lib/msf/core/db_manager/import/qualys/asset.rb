module Msf::DBManager::Import::Qualys::Asset
  # Takes QID numbers and finds the discovered services in
  # a qualys_asset_xml.
  def find_qualys_asset_ports(i,host,wspace,hobj,task_id)
    return unless (i == Msf::DBManager::Import::Qualys::TCP_QID || i == Msf::DBManager::Import::Qualys::UDP_QID)
    proto = i == Msf::DBManager::Import::Qualys::TCP_QID ? 'tcp' : 'udp'
    qid = host.xpath("VULN_INFO_LIST/VULN_INFO/QID[@id='qid_#{i}']").first
    qid_result = qid.parent.xpath("RESULT[@format='table']") if qid
    hports = qid_result.first.text if qid_result
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
    doc.xpath("/ASSET_DATA_REPORT/GLOSSARY/VULN_DETAILS_LIST/VULN_DETAILS").each do |vuln|
      qid_el = vuln.xpath('QID')
      next unless qid_el && qid_el.first
      qid = qid_el.first.text
      vuln_refs[qid] ||= []
      vuln.xpath('CVE_ID_LIST/CVE_ID').each do |ref|
        id = ref.xpath("ID").first&.text
        vuln_refs[qid].push(id) if id
      end
      vuln.xpath('BUGTRAQ_ID_LIST/BUGTRAQ_ID').each do |ref|
        id = ref.xpath("ID").first&.text
        vuln_refs[qid].push("BID-#{id}") if id
      end
    end
    return vuln_refs
  end

  # Pull out vulnerabilities that have at least one matching
  # ref -- many "vulns" are not vulns, just audit information.
  def find_qualys_asset_vulns(host,wspace,hobj,vuln_refs,task_id,&block)
    host.xpath("VULN_INFO_LIST/VULN_INFO").each do |vi|
      next unless vi.xpath("QID").first
      vi.xpath("QID").each do |qid|
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
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    doc = Nokogiri.XML(data)
    vuln_refs = find_qualys_asset_vuln_refs(doc)

    # 2nd pass, actually grab the hosts.
    doc.xpath("/ASSET_DATA_REPORT/HOST_LIST/HOST").each do |host|
      hobj = nil
      addr_el = host.xpath("IP").first
      addr = addr_el.text if addr_el
      next unless validate_ips(addr)
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end
      netbios_el = host.xpath("NETBIOS").first
      dns_el = host.xpath("DNS").first
      hname = ( # Prefer NetBIOS over DNS
        (netbios_el.text if netbios_el) ||
         (dns_el.text if dns_el) ||
         "" )
      hobj = report_host(:workspace => wspace, :host => addr, :name => hname, :state => Msf::HostState::Alive, :task => args[:task])
      report_import_note(wspace,hobj)

      os_el = host.xpath("OPERATING_SYSTEM").first
      if os_el
        hos = os_el.text
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
