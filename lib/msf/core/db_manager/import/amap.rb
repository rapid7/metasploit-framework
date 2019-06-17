module Msf::DBManager::Import::Amap
  def import_amap_log(args={}, &block)
    data = args[:data]
    wspace = args[:workspace] || args[:wspace]
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    data.each_line do |line|
      next if line =~ /^#/
      next if line !~ /^Protocol on ([^:]+):([^\x5c\x2f]+)[\x5c\x2f](tcp|udp) matches (.*)$/n
      addr   = $1
      next if bl.include? addr
      port   = $2.to_i
      proto  = $3.downcase
      name   = $4
      host = find_or_create_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive, :task => args[:task])
      next if not host
      yield(:address,addr) if block
      info = {
        :workspace => wspace,
        :task => args[:task],
        :host => host,
        :proto => proto,
        :port => port
      }
      if name != "unidentified"
        info[:name] = name
      end
      service = find_or_create_service(info)
    end
  end

  def import_amap_log_file(args={})
    filename = args[:filename]
    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end

    case import_filetype_detect(data)
    when :amap_log
      import_amap_log(args.merge(:data => data))
    when :amap_mlog
      import_amap_mlog(args.merge(:data => data))
    else
      raise Msf::DBImportError.new("Could not determine file type")
    end
  end

  def import_amap_mlog(args={}, &block)
    data = args[:data]
    wspace = args[:workspace] || args[:wspace]
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    data.each_line do |line|
      next if line =~ /^#/
      r = line.split(':')
      next if r.length < 6

      addr   = r[0]
      next if bl.include? addr
      port   = r[1].to_i
      proto  = r[2].downcase
      status = r[3]
      name   = r[5]
      next if status != "open"

      host = find_or_create_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive, :task => args[:task])
      next if not host
      yield(:address,addr) if block
      info = {
        :workspace => wspace,
        :task => args[:task],
        :host => host,
        :proto => proto,
        :port => port
      }
      if name != "unidentified"
        info[:name] = name
      end
      service = find_or_create_service(info)
    end
  end
end
