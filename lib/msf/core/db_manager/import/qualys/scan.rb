module Msf::DBManager::Import::Qualys::Scan
  def import_qualys_scan_xml(args={}, &block)
    data = args[:data]
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []


    doc = Nokogiri.XML(data)
    doc.xpath('/SCAN/IP').each do |host|
      hobj = nil
      addr  = host.attr('value')
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end
      hname = host.attr('name') || ''

      hobj = report_host(:workspace => wspace, :host => addr, :name => hname, :state => Msf::HostState::Alive, :task => args[:task])
      report_import_note(wspace,hobj)

      os_el = host.xpath("OS").first
      if os_el
        hos = os_el.text
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
      services_tcp = host.xpath("SERVICES/CAT/SERVICE[@number='#{Msf::DBManager::Import::Qualys::TCP_QID}']/RESULT").first
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
      services_udp = host.xpath("SERVICES/CAT/SERVICE[@number='#{Msf::DBManager::Import::Qualys::UDP_QID}']/RESULT").first
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
      host.xpath('VULNS/CAT | PRACTICES/CAT').each do |cat|
        port = cat.attr('port')
        protocol = cat.attr('protocol')
        cat.xpath('VULN | PRACTICE').each do |vuln|
          refs = []
          qid = vuln.attr('number')
          severity = vuln.attr('severity')
          title = vuln.xpath('TITLE').first&.text
          vuln.xpath('VENDOR_REFERENCE_LIST/VENDOR_REFERENCE').each do |ref|
            id = ref.xpath('ID').first&.text
            refs.push(id) if id
          end
          vuln.xpath('CVE_ID_LIST/CVE_ID').each do |ref|
            id = ref.xpath("ID").first&.text
            refs.push(id) if id
          end
          vuln.xpath('BUGTRAQ_ID_LIST/BUGTRAQ_ID').each do |ref|
            id = ref.xpath("ID").first&.text
            refs.push("BID-#{id}") if id
          end

          handle_qualys(wspace, hobj, port, protocol, qid, severity, refs, nil,title, args[:task])
        end
      end
    end
  end

  #
  # Import Qualys' Scan xml output
  #
  def import_qualys_scan_xml_file(args={})
    filename = args[:filename]

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_qualys_scan_xml(args.merge(:data => data))
  end
end
