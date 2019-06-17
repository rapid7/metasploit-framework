module Msf::DBManager::Import::Nessus::XML::V1
  def import_nessus_xml(args={}, &block)
    data = args[:data]
    wspace = args[:workspace] || args[:wspace]
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
        addr = item.elements['data'].text.match(/([0-9\x2e]+) resolves as/n)[1]
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
end
