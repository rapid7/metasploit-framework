module Msf::DBManager::Import::Qualys::Scan
  def import_qualys_scan_xml(args={}, &block)
    data = args[:data]
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
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
            refs.push('CVE-' + /C..-([0-9\-]{9,})/.match(ref.elements['ID'].text.to_s)[1])
          end
          vuln.elements.each('BUGTRAQ_ID_LIST/BUGTRAQ_ID') do |ref|
            refs.push('BID-' + ref.elements['ID'].text.to_s)
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
