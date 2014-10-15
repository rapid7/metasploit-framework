module Msf::DBManager::Import::Nessus::XML::V2
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
end