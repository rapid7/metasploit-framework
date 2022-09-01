module Msf::DBManager::Import::Nessus::NBE
  # There is no place the NBE actually stores the plugin name used to
  # scan. You get "Security Note" or "Security Warning," and that's it.
  def import_nessus_nbe(args={}, &block)
    nbe_data = args[:data]
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
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
      addr,hname = data.match(/([0-9\x2e]+) resolves as (.+)\x2e\\n/n)[1,2]
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

  #
  # Import Nessus NBE files
  #
  def import_nessus_nbe_file(args={})
    filename = args[:filename]

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nessus_nbe(args.merge(:data => data))
  end
end
