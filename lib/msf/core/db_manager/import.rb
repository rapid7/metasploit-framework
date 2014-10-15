#
# Standard library
#

require 'csv'
require 'fileutils'
require 'tmpdir'
require 'uri'

#
# Gems
#

require 'packetfu'
require 'rex/parser/burp_session_nokogiri'
require 'rex/parser/ci_nokogiri'
require 'rex/parser/foundstone_nokogiri'
require 'rex/parser/fusionvm_nokogiri'
require 'rex/parser/mbsa_nokogiri'
require 'rex/parser/nessus_xml'
require 'rex/parser/netsparker_xml'
require 'rex/parser/nexpose_raw_nokogiri'
require 'rex/parser/nexpose_simple_nokogiri'
require 'rex/parser/nexpose_xml'
require 'rex/parser/nmap_nokogiri'
require 'rex/parser/nmap_xml'
require 'rex/parser/openvas_nokogiri'
require 'rex/parser/outpost24_nokogiri'
require 'rex/parser/retina_xml'
require 'rex/parser/wapiti_nokogiri'

module Msf::DBManager::Import
  autoload :Acunetix, 'msf/core/db_manager/import/acunetix'
  autoload :Amap, 'msf/core/db_manager/import/amap'
  autoload :Appscan, 'msf/core/db_manager/import/appscan'
  autoload :IP360, 'msf/core/db_manager/import/ip360'
  autoload :MsfXml, 'msf/core/db_manager/import/msf_xml'
  autoload :Qualys, 'msf/core/db_manager/import/qualys'

  include Msf::DBManager::Import::Acunetix
  include Msf::DBManager::Import::Amap
  include Msf::DBManager::Import::Appscan
  include Msf::DBManager::Import::IP360
  include Msf::DBManager::Import::MsfXml
  include Msf::DBManager::Import::Qualys

  # If hex notation is present, turn them into a character.
  def dehex(str)
    hexen = str.scan(/\x5cx[0-9a-fA-F]{2}/n)
    hexen.each { |h|
      str.gsub!(h,h[2,2].to_i(16).chr)
    }
    return str
  end

  # A way to sneak the yield back into the db importer.
  # Used by the SAX parsers.
  def emit(sym,data,&block)
    yield(sym,data)
  end

  # A dispatcher method that figures out the data's file type,
  # and sends it off to the appropriate importer. Note that
  # import_file_detect will raise an error if the filetype
  # is unknown.
  def import(args={}, &block)
    data = args[:data] || args['data']
    ftype = import_filetype_detect(data)
    yield(:filetype, @import_filedata[:type]) if block
    self.send "import_#{ftype}".to_sym, args, &block
  end

  def import_burp_session_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::BurpSessionDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::BurpSessionDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_burp_session_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      # Rex::Parser.reload("burp_session_nokogiri.rb")
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_burp_session_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_burp_session_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  def import_ci_noko_stream(args, &block)
    if block
      doc = Rex::Parser::CIDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::CI.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_ci_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_ci_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_ci_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  #
  # Generic importer that automatically determines the file type being
  # imported.  Since this looks for vendor-specific strings in the given
  # file, there shouldn't be any false detections, but no guarantees.
  #
  def import_file(args={}, &block)
    filename = args[:filename] || args['filename']
    wspace = args[:wspace] || args['wspace'] || workspace
    @import_filedata            = {}
    @import_filedata[:filename] = filename

    data = ""
    ::File.open(filename, 'rb') do |f|
      # This check is the largest (byte-wise) that we need to do
      # since the other 4-byte checks will be subsets of this larger one.
      data = f.read(Metasploit::Credential::Exporter::Pwdump::FILE_ID_STRING.size)
    end
    if data.nil?
      raise DBImportError.new("Zero-length file")
    end

    if data.index(Metasploit::Credential::Exporter::Pwdump::FILE_ID_STRING)
      data = ::File.open(filename, 'rb')
    else
      case data[0,4]
      when "PK\x03\x04"
        data = Zip::File.open(filename)
      when "\xd4\xc3\xb2\xa1", "\xa1\xb2\xc3\xd4"
        data = PacketFu::PcapFile.new(:filename => filename)
      else
        ::File.open(filename, 'rb') do |f|
          sz = f.stat.size
          data = f.read(sz)
        end
      end
    end


    if block
      import(args.merge(:data => data)) { |type,data| yield type,data }
    else
      import(args.merge(:data => data))
    end
  end

  # Returns one of the following:
  #
  # :acunetix_xml
  # :amap_log
  # :amap_mlog
  # :appscan_xml
  # :burp_session_xml
  # :ci_xml
  # :foundstone_xml
  # :fusionvm_xml
  # :ip360_aspl_xml
  # :ip360_xml_v3
  # :ip_list
  # :libpcap
  # :mbsa_xml
  # :msf_cred_dump_zip
  # :msf_pwdump
  # :msf_xml
  # :msf_zip
  # :nessus_nbe
  # :nessus_xml
  # :nessus_xml_v2
  # :netsparker_xml
  # :nexpose_rawxml
  # :nexpose_simplexml
  # :nikto_xml
  # :nmap_xml
  # :openvas_new_xml
  # :openvas_xml
  # :outpost24_xml
  # :qualys_asset_xml
  # :qualys_scan_xml
  # :retina_xml
  # :spiceworks_csv
  # :wapiti_xml
  #
  # If there is no match, an error is raised instead.
  #
  # @raise DBImportError if the type can't be detected
  def import_filetype_detect(data)

    if data and data.kind_of? Zip::File
      if data.entries.empty?
        raise DBImportError.new("The zip file provided is empty.")
      end

      @import_filedata ||= {}
      @import_filedata[:zip_filename] = File.split(data.to_s).last
      @import_filedata[:zip_basename] = @import_filedata[:zip_filename].gsub(/\.zip$/,"")
      @import_filedata[:zip_entry_names] = data.entries.map {|x| x.name}

      if @import_filedata[:zip_entry_names].include?(Metasploit::Credential::Importer::Zip::MANIFEST_FILE_NAME)
        @import_filedata[:type] = "Metasploit Credential Dump"
        return :msf_cred_dump_zip
      end

      xml_files = @import_filedata[:zip_entry_names].grep(/^(.*)\.xml$/)

      # TODO This check for our zip export should be more extensive
      if xml_files.empty?
        raise DBImportError.new("The zip file provided is not a Metasploit Zip Export")
      end

      @import_filedata[:zip_xml] = xml_files.first
      @import_filedata[:type] = "Metasploit Zip Export"

      return :msf_zip
    end

    if data and data.kind_of? PacketFu::PcapFile
      # Don't check for emptiness here because unlike other formats, we
      # haven't read any actual data in yet, only magic bytes to discover
      # that this is indeed a pcap file.
      #raise DBImportError.new("The pcap file provided is empty.") if data.body.empty?
      @import_filedata ||= {}
      @import_filedata[:type] = "Libpcap Packet Capture"
      return :libpcap
    end

    # msfpwdump
    if data.present? && data.kind_of?(::File)
      @import_filedata[:type] = "Metasploit PWDump Export"
      return :msf_pwdump
    end

    # This is a text string, lets make sure its treated as binary
    data = data.unpack("C*").pack("C*")
    if data and data.to_s.strip.length == 0
      raise DBImportError.new("The data provided to the import function was empty")
    end

    # Parse the first line or 4k of data from the file
    di = data.index("\n") || 4096

    firstline = data[0, di]
    @import_filedata ||= {}
    if (firstline.index("<NeXposeSimpleXML"))
      @import_filedata[:type] = "NeXpose Simple XML"
      return :nexpose_simplexml
    elsif (firstline.index("<FusionVM"))
      @import_filedata[:type] = "FusionVM XML"
      return :fusionvm_xml
    elsif (firstline.index("<NexposeReport"))
      @import_filedata[:type] = "NeXpose XML Report"
      return :nexpose_rawxml
    elsif (firstline.index("Name,Manufacturer,Device Type,Model,IP Address,Serial Number,Location,Operating System"))
      @import_filedata[:type] = "Spiceworks CSV Export"
      return :spiceworks_csv
    elsif (firstline.index("<scanJob>"))
      @import_filedata[:type] = "Retina XML"
      return :retina_xml
    elsif (firstline.index(/<get_reports_response status=['"]200['"] status_text=['"]OK['"]>/))
      @import_filedata[:type] = "OpenVAS XML"
      return :openvas_new_xml
    elsif (firstline.index(/<report id=['"]/))
      @import_filedata[:type] = "OpenVAS XML"
      return :openvas_new_xml
    elsif (firstline.index("<NessusClientData>"))
      @import_filedata[:type] = "Nessus XML (v1)"
      return :nessus_xml
    elsif (firstline.index("<SecScan ID="))
      @import_filedata[:type] = "Microsoft Baseline Security Analyzer"
      return :mbsa_xml
    elsif (data[0,1024] =~ /<!ATTLIST\s+items\s+burpVersion/)
      @import_filedata[:type] = "Burp Session XML"
      return :burp_session_xml
    elsif (firstline.index("<?xml"))
      # it's xml, check for root tags we can handle
      line_count = 0
      data.each_line { |line|
        line =~ /<([a-zA-Z0-9\-\_]+)[ >]/

        case $1
        when "niktoscan"
          @import_filedata[:type] = "Nikto XML"
          return :nikto_xml
        when "nmaprun"
          @import_filedata[:type] = "Nmap XML"
          return :nmap_xml
        when "openvas-report"
          @import_filedata[:type] = "OpenVAS Report"
          return :openvas_xml
        when "NessusClientData"
          @import_filedata[:type] = "Nessus XML (v1)"
          return :nessus_xml
        when "NessusClientData_v2"
          @import_filedata[:type] = "Nessus XML (v2)"
          return :nessus_xml_v2
        when "SCAN"
          @import_filedata[:type] = "Qualys Scan XML"
          return :qualys_scan_xml
        when "report"
          @import_filedata[:type] = "Wapiti XML"
          return :wapiti_xml
        when "ASSET_DATA_REPORT"
          @import_filedata[:type] = "Qualys Asset XML"
          return :qualys_asset_xml
        when /MetasploitExpressV[1234]/
          @import_filedata[:type] = "Metasploit XML"
          return :msf_xml
        when /MetasploitV4/
          @import_filedata[:type] = "Metasploit XML"
          return :msf_xml
        when /netsparker/
          @import_filedata[:type] = "NetSparker XML"
          return :netsparker_xml
        when /audits?/ # <audit> and <audits> are both valid for nCircle. wtfmate.
          @import_filedata[:type] = "IP360 XML v3"
          return :ip360_xml_v3
        when /ontology/
          @import_filedata[:type] = "IP360 ASPL"
          return :ip360_aspl_xml
        when /ReportInfo/
          @import_filedata[:type] = "Foundstone"
          return :foundstone_xml
        when /ScanGroup/
          @import_filedata[:type] = "Acunetix"
          return :acunetix_xml
        when /AppScanInfo/ # Actually the second line
          @import_filedata[:type] = "Appscan"
          return :appscan_xml
        when "entities"
          if  line =~ /creator.*\x43\x4f\x52\x45\x20\x49\x4d\x50\x41\x43\x54/ni
            @import_filedata[:type] = "CI"
            return :ci_xml
          end
        when "main"
          @import_filedata[:type] = "Outpost24 XML"
          return :outpost24_xml
        else
          # Give up if we haven't hit the root tag in the first few lines
          break if line_count > 10
        end
        line_count += 1
      }
    elsif (firstline.index("timestamps|||scan_start"))
      @import_filedata[:type] = "Nessus NBE Report"
      # then it's a nessus nbe
      return :nessus_nbe
    elsif (firstline.index("# amap v"))
      # then it's an amap mlog
      @import_filedata[:type] = "Amap Log -m"
      return :amap_mlog
    elsif (firstline.index("amap v"))
      # then it's an amap log
      @import_filedata[:type] = "Amap Log"
      return :amap_log
    elsif ipv46_validator(firstline)
      # then its an IP list
      @import_filedata[:type] = "IP Address List"
      return :ip_list
    elsif (data[0,1024].index("<netsparker"))
      @import_filedata[:type] = "NetSparker XML"
      return :netsparker_xml
    elsif (firstline.index("# Metasploit PWDump Export"))
      # then it's a Metasploit PWDump export
      @import_filedata[:type] = "Metasploit PWDump Export"
      return :msf_pwdump
    end

    raise DBImportError.new("Could not automatically determine file type")
  end

  def import_foundstone_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::FoundstoneDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::FoundstoneDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_foundstone_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_foundstone_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_foundstone_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  def import_fusionvm_xml(args={})
    args[:wspace] ||= workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    doc = Rex::Parser::FusionVMDocument.new(args,self)
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_ip_list(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    data.each_line do |ip|
      ip.strip!
      if bl.include? ip
        next
      else
        yield(:address,ip) if block
      end
      host = find_or_create_host(:workspace => wspace, :host=> ip, :state => Msf::HostState::Alive, :task => args[:task])
    end
  end

  def import_ip_list_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_ip_list(args.merge(:data => data))
  end

  # The libpcap file format is handled by PacketFu for data
  # extraction. TODO: Make this its own mixin, and possibly
  # extend PacketFu to do better stream analysis on the fly.
  def import_libpcap(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    # seen_hosts is only used for determining when to yield an address. Once we get
    # some packet analysis going, the values will have all sorts of info. The plan
    # is to ru through all the packets as a first pass and report host and service,
    # then, once we have everything parsed, we can reconstruct sessions and ngrep
    # out things like authentication sequences, examine ttl's and window sizes, all
    # kinds of crazy awesome stuff like that.
    seen_hosts = {}
    decoded_packets = 0
    last_count = 0
    data.read_packet_bytes do |p|
      if (decoded_packets >= last_count + 1000) and block
        yield(:pcap_count, decoded_packets)
        last_count = decoded_packets
      end
      decoded_packets += 1

      pkt = PacketFu::Packet.parse(p) rescue next # Just silently skip bad packets

      next unless pkt.is_ip? # Skip anything that's not IP. Technically, not Ethernet::Ip
      next if pkt.is_tcp? && (pkt.tcp_src == 0 || pkt.tcp_dst == 0) # Skip port 0
      next if pkt.is_udp? && (pkt.udp_src == 0 || pkt.udp_dst == 0) # Skip port 0
      saddr = pkt.ip_saddr
      daddr = pkt.ip_daddr

      # Handle blacklists and obviously useless IP addresses, and report the host.
      next if (bl | [saddr,daddr]).size == bl.size # Both hosts are blacklisted, skip everything.
      unless( bl.include?(saddr) || rfc3330_reserved(saddr))
        yield(:address,saddr) if block and !seen_hosts.keys.include?(saddr)
        unless seen_hosts[saddr]
          report_host(
              :workspace => wspace,
              :host      => saddr,
              :state     => Msf::HostState::Alive,
              :task      => args[:task]
          )
        end
        seen_hosts[saddr] ||= []

      end
      unless( bl.include?(daddr) || rfc3330_reserved(daddr))
        yield(:address,daddr) if block and !seen_hosts.keys.include?(daddr)
        unless seen_hosts[daddr]
          report_host(
              :workspace => wspace,
              :host      => daddr,
              :state     => Msf::HostState::Alive,
              :task      => args[:task]
          )
        end
        seen_hosts[daddr] ||= []
      end

      if pkt.is_tcp? # First pass on TCP packets
        if (pkt.tcp_flags.syn == 1 and pkt.tcp_flags.ack == 1) or # Oh, this kills me
          pkt.tcp_src < 1024 # If it's a low port, assume it's a proper service.
          if seen_hosts[saddr]
            unless seen_hosts[saddr].include? [pkt.tcp_src,"tcp"]
              report_service(
                  :workspace => wspace, :host => saddr,
                  :proto     => "tcp", :port => pkt.tcp_src,
                  :state     => Msf::ServiceState::Open,
                  :task      => args[:task]
              )
              seen_hosts[saddr] << [pkt.tcp_src,"tcp"]
              yield(:service,"%s:%d/%s" % [saddr,pkt.tcp_src,"tcp"])
            end
          end
        end
      elsif pkt.is_udp? # First pass on UDP packets
        if pkt.udp_src == pkt.udp_dst # Very basic p2p detection.
          [saddr,daddr].each do |xaddr|
            if seen_hosts[xaddr]
              unless seen_hosts[xaddr].include? [pkt.udp_src,"udp"]
                report_service(
                    :workspace => wspace, :host => xaddr,
                    :proto     => "udp", :port => pkt.udp_src,
                    :state     => Msf::ServiceState::Open,
                    :task      => args[:task]
                )
                seen_hosts[xaddr] << [pkt.udp_src,"udp"]
                yield(:service,"%s:%d/%s" % [xaddr,pkt.udp_src,"udp"])
              end
            end
          end
        elsif pkt.udp_src < 1024 # Probably a service
          if seen_hosts[saddr]
            unless seen_hosts[saddr].include? [pkt.udp_src,"udp"]
              report_service(
                  :workspace => wspace, :host => saddr,
                  :proto     => "udp", :port => pkt.udp_src,
                  :state     => Msf::ServiceState::Open,
                  :task      => args[:task]
              )
              seen_hosts[saddr] << [pkt.udp_src,"udp"]
              yield(:service,"%s:%d/%s" % [saddr,pkt.udp_src,"udp"])
            end
          end
        end
      end # tcp or udp

      inspect_single_packet(pkt,wspace,args)

    end # data.body.map

    # Right about here, we should have built up some streams for some stream analysis.
    # Not sure what form that will take, but people like shoving many hundreds of
    # thousands of packets through this thing, so it'll need to be memory efficient.

  end

  def import_libpcap_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = PacketFu::PcapFile.new(:filename => filename)
    import_libpcap(args.merge(:data => data))
  end

  def import_mbsa_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::MbsaDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::MbsaDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_mbsa_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_mbsa_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_mbsa_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  # Imports loot, tasks, and reports from an MSF ZIP report.
  # XXX: This function is stupidly long. It needs to be refactored.
  def import_msf_collateral(args={}, &block)
    data = ::File.open(args[:filename], "rb") {|f| f.read(f.stat.size)}
    wspace = args[:wspace] || args['wspace'] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    basedir = args[:basedir] || args['basedir'] || ::File.join(Msf::Config.data_directory, "msf")

    allow_yaml = false
    btag = nil

    doc = rexmlify(data)
    if doc.elements["MetasploitExpressV1"]
      m_ver = 1
      allow_yaml = true
      btag = "MetasploitExpressV1"
    elsif doc.elements["MetasploitExpressV2"]
      m_ver = 2
      allow_yaml = true
      btag = "MetasploitExpressV2"
    elsif doc.elements["MetasploitExpressV3"]
      m_ver = 3
      btag = "MetasploitExpressV3"
    elsif doc.elements["MetasploitExpressV4"]
      m_ver = 4
      btag = "MetasploitExpressV4"
    elsif doc.elements["MetasploitV4"]
      m_ver = 4
      btag = "MetasploitV4"
    else
      m_ver = nil
    end
    unless m_ver and btag
      raise DBImportError.new("Unsupported Metasploit XML document format")
    end

    host_info = {}
    doc.elements.each("/#{btag}/hosts/host") do |host|
      host_info[host.elements["id"].text.to_s.strip] = nils_for_nulls(host.elements["address"].text.to_s.strip)
    end

    # Import Loot
    doc.elements.each("/#{btag}/loots/loot") do |loot|
      next if bl.include? host_info[loot.elements["host-id"].text.to_s.strip]
      loot_info              = {}
      loot_info[:host]       = host_info[loot.elements["host-id"].text.to_s.strip]
      loot_info[:workspace]  = args[:wspace]
      loot_info[:ctype]      = nils_for_nulls(loot.elements["content-type"].text.to_s.strip)
      loot_info[:info]       = nils_for_nulls(unserialize_object(loot.elements["info"], allow_yaml))
      loot_info[:ltype]      = nils_for_nulls(loot.elements["ltype"].text.to_s.strip)
      loot_info[:name]       = nils_for_nulls(loot.elements["name"].text.to_s.strip)
      loot_info[:created_at] = nils_for_nulls(loot.elements["created-at"].text.to_s.strip)
      loot_info[:updated_at] = nils_for_nulls(loot.elements["updated-at"].text.to_s.strip)
      loot_info[:name]       = nils_for_nulls(loot.elements["name"].text.to_s.strip)
      loot_info[:orig_path]  = nils_for_nulls(loot.elements["path"].text.to_s.strip)
      loot_info[:task]       = args[:task]
      tmp = args[:ifd][:zip_tmp]
      loot_info[:orig_path].gsub!(/^\./,tmp) if loot_info[:orig_path]
      if !loot.elements["service-id"].text.to_s.strip.empty?
        unless loot.elements["service-id"].text.to_s.strip == "NULL"
          loot_info[:service] = loot.elements["service-id"].text.to_s.strip
        end
      end

      # Only report loot if we actually have it.
      # TODO: Copypasta. Seperate this out.
      if ::File.exists? loot_info[:orig_path]
        loot_dir = ::File.join(basedir,"loot")
        loot_file = ::File.split(loot_info[:orig_path]).last
        if ::File.exists? loot_dir
          unless (::File.directory?(loot_dir) && ::File.writable?(loot_dir))
            raise DBImportError.new("Could not move files to #{loot_dir}")
          end
        else
          ::FileUtils.mkdir_p(loot_dir)
        end
        new_loot = ::File.join(loot_dir,loot_file)
        loot_info[:path] = new_loot
        if ::File.exists?(new_loot)
          ::File.unlink new_loot # Delete it, and don't report it.
        else
          report_loot(loot_info) # It's new, so report it.
        end
        ::FileUtils.copy(loot_info[:orig_path], new_loot)
        yield(:msf_loot, new_loot) if block
      end
    end

    # Import Tasks
    doc.elements.each("/#{btag}/tasks/task") do |task|
      task_info = {}
      task_info[:workspace] = args[:wspace]
      # Should user be imported (original) or declared (the importing user)?
      task_info[:user] = nils_for_nulls(task.elements["created-by"].text.to_s.strip)
      task_info[:desc] = nils_for_nulls(task.elements["description"].text.to_s.strip)
      task_info[:info] = nils_for_nulls(unserialize_object(task.elements["info"], allow_yaml))
      task_info[:mod] = nils_for_nulls(task.elements["module"].text.to_s.strip)
      task_info[:options] = nils_for_nulls(task.elements["options"].text.to_s.strip)
      task_info[:prog] = nils_for_nulls(task.elements["progress"].text.to_s.strip).to_i
      task_info[:created_at] = nils_for_nulls(task.elements["created-at"].text.to_s.strip)
      task_info[:updated_at] = nils_for_nulls(task.elements["updated-at"].text.to_s.strip)
      if !task.elements["completed-at"].text.to_s.empty?
        task_info[:completed_at] = nils_for_nulls(task.elements["completed-at"].text.to_s.strip)
      end
      if !task.elements["error"].text.to_s.empty?
        task_info[:error] = nils_for_nulls(task.elements["error"].text.to_s.strip)
      end
      if !task.elements["result"].text.to_s.empty?
        task_info[:result] = nils_for_nulls(task.elements["result"].text.to_s.strip)
      end
      task_info[:orig_path] = nils_for_nulls(task.elements["path"].text.to_s.strip)
      tmp = args[:ifd][:zip_tmp]
      task_info[:orig_path].gsub!(/^\./,tmp) if task_info[:orig_path]

      # Only report a task if we actually have it.
      # TODO: Copypasta. Seperate this out.
      if ::File.exists? task_info[:orig_path]
        tasks_dir = ::File.join(basedir,"tasks")
        task_file = ::File.split(task_info[:orig_path]).last
        if ::File.exists? tasks_dir
          unless (::File.directory?(tasks_dir) && ::File.writable?(tasks_dir))
            raise DBImportError.new("Could not move files to #{tasks_dir}")
          end
        else
          ::FileUtils.mkdir_p(tasks_dir)
        end
        new_task = ::File.join(tasks_dir,task_file)
        task_info[:path] = new_task
        if ::File.exists?(new_task)
          ::File.unlink new_task # Delete it, and don't report it.
        else
          report_task(task_info) # It's new, so report it.
        end
        ::FileUtils.copy(task_info[:orig_path], new_task)
        yield(:msf_task, new_task) if block
      end
    end

    # Import Reports
    doc.elements.each("/#{btag}/reports/report") do |report|
      import_report(report, args, basedir)
    end
  end

  # Import credentials given a path to a valid manifest file
  #
  # @param creds_dump_manifest_path [String]
  # @param workspace [Mdm::Workspace] Default: {#workspace}
  # @return [void]
  def import_msf_cred_dump(creds_dump_manifest_path, workspace)
    manifest_file = File.open(creds_dump_manifest_path)
    origin = Metasploit::Credential::Origin::Import.create!(filename: File.basename(creds_dump_manifest_path))
    importer = Metasploit::Credential::Importer::Core.new(workspace: workspace, input: manifest_file, origin: origin)
    importer.import!
  end

  # Import credentials given a path to a valid manifest file
  #
  # @option args [String] :filename
  # @option args [Mdm::Workspace] :wspace Default: {#workspace}
  # @return [void]
  def import_msf_cred_dump_zip(args = {})
    wspace = args[:wspace] || workspace
    origin = Metasploit::Credential::Origin::Import.create!(filename: File.basename(args[:filename]))
    importer = Metasploit::Credential::Importer::Zip.new(workspace: wspace, input: File.open(args[:filename]), origin: origin)
    importer.import!
    nil
  end

  # Import a Metasploit XML file.
  def import_msf_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_msf_xml(args.merge(:data => data))
  end

  # Perform in an import of an msfpwdump file
  def import_msf_pwdump(args={}, &block)
    filename = File.basename(args[:data].path)
    wspace   = args[:wspace] || workspace
    origin   = Metasploit::Credential::Origin::Import.create!(filename: filename)
    importer = Metasploit::Credential::Importer::Pwdump.new(input: args[:data], workspace: wspace, filename: filename, origin:origin)
    importer.import!
    importer.input.close unless importer.input.closed?
  end

  # Import a Metasploit Express ZIP file. Note that this requires
  # a fair bit of filesystem manipulation, and is very much tied
  # up with the Metasploit Express ZIP file format export (for
  # obvious reasons). In the event directories exist, they will
  # be reused. If target files exist, they will be overwritten.
  #
  # XXX: Refactor so it's not quite as sanity-blasting.
  def import_msf_zip(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    new_tmp = ::File.join(Dir::tmpdir,"msf","imp_#{Rex::Text::rand_text_alphanumeric(4)}",@import_filedata[:zip_basename])
    if ::File.exists? new_tmp
      unless (::File.directory?(new_tmp) && ::File.writable?(new_tmp))
        raise DBImportError.new("Could not extract zip file to #{new_tmp}")
      end
    else
      FileUtils.mkdir_p(new_tmp)
    end
    @import_filedata[:zip_tmp] = new_tmp

    # Grab the list of unique basedirs over all entries.
    @import_filedata[:zip_tmp_subdirs] = @import_filedata[:zip_entry_names].map {|x| ::File.split(x)}.map {|x| x[0]}.uniq.reject {|x| x == "."}

    # mkdir all of the base directores we just pulled out, if they don't
    # already exist
    @import_filedata[:zip_tmp_subdirs].each {|sub|
      tmp_subdirs = ::File.join(@import_filedata[:zip_tmp],sub)
      if File.exists? tmp_subdirs
        unless (::File.directory?(tmp_subdirs) && File.writable?(tmp_subdirs))
          # if it exists but we can't write to it, give up
          raise DBImportError.new("Could not extract zip file to #{tmp_subdirs}")
        end
      else
        ::FileUtils.mkdir(tmp_subdirs)
      end
    }

    data.entries.each do |e|
      target = ::File.join(@import_filedata[:zip_tmp], e.name)
      data.extract(e,target)

      if target =~ /\.xml\z/
        target_data = ::File.open(target, "rb") {|f| f.read 1024}
        if import_filetype_detect(target_data) == :msf_xml
          @import_filedata[:zip_extracted_xml] = target
        end
      end
    end

    # Import any creds if there are some in the import file
    Dir.entries(@import_filedata[:zip_tmp]).each do |entry|
      if entry =~ /^.*#{Regexp.quote(Metasploit::Credential::Exporter::Core::CREDS_DUMP_FILE_IDENTIFIER)}.*/
        manifest_file_path = File.join(@import_filedata[:zip_tmp], entry, Metasploit::Credential::Importer::Zip::MANIFEST_FILE_NAME)
        if File.exists? manifest_file_path
          import_msf_cred_dump(manifest_file_path, wspace)
        end
      end
    end

    # This will kick the newly-extracted XML file through
    # the import_file process all over again.
    if @import_filedata[:zip_extracted_xml]
      new_args = args.dup
      new_args[:filename] = @import_filedata[:zip_extracted_xml]
      new_args[:data] = nil
      new_args[:ifd] = @import_filedata.dup
      if block
        import_file(new_args, &block)
      else
        import_file(new_args)
      end
    end

    # Kick down to all the MSFX ZIP specific items
    if block
      import_msf_collateral(new_args, &block)
    else
      import_msf_collateral(new_args)
    end
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
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nessus_nbe(args.merge(:data => data))
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

  # Process NetSparker XML
  def import_netsparker_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    addr = nil
    parser = Rex::Parser::NetSparkerXMLStreamParser.new
    parser.on_found_vuln = Proc.new do |vuln|
      data = {:workspace => wspace}

      # Parse the URL
      url  = vuln['url']
      return if not url

      # Crack the URL into a URI
      uri = URI(url) rescue nil
      return if not uri

      # Resolve the host and cache the IP
      if not addr
        baddr = Rex::Socket.addr_aton(uri.host) rescue nil
        if baddr
          addr = Rex::Socket.addr_ntoa(baddr)
          yield(:address, addr) if block
        end
      end

      # Bail early if we have no IP address
      if not addr
        raise Interrupt, "Not a valid IP address"
      end

      if bl.include?(addr)
        raise Interrupt, "IP address is on the blacklist"
      end

      data[:host]  = addr
      data[:vhost] = uri.host
      data[:port]  = uri.port
      data[:ssl]   = (uri.scheme == "ssl")

      body = nil
      # First report a web page
      if vuln['response']
        headers = {}
        code    = 200
        head,body = vuln['response'].to_s.split(/\r?\n\r?\n/, 2)
        if body

          if head =~ /^HTTP\d+\.\d+\s+(\d+)\s*/
            code = $1.to_i
          end

          headers = {}
          head.split(/\r?\n/).each do |line|
            hname,hval = line.strip.split(/\s*:\s*/, 2)
            next if hval.to_s.strip.empty?
            headers[hname.downcase] ||= []
            headers[hname.downcase] << hval
          end

          info = {
            :path     => uri.path,
            :query    => uri.query,
            :code     => code,
            :body     => body,
            :headers  => headers,
            :task     => args[:task]
          }
          info.merge!(data)

          if headers['content-type']
            info[:ctype] = headers['content-type'][0]
          end

          if headers['set-cookie']
            info[:cookie] = headers['set-cookie'].join("\n")
          end

          if headers['authorization']
            info[:auth] = headers['authorization'].join("\n")
          end

          if headers['location']
            info[:location] = headers['location'][0]
          end

          if headers['last-modified']
            info[:mtime] = headers['last-modified'][0]
          end

          # Report the web page to the database
          report_web_page(info)

          yield(:web_page, url) if block
        end
      end # End web_page reporting


      details = netsparker_vulnerability_map(vuln)

      method = netsparker_method_map(vuln)
      pname  = netsparker_pname_map(vuln)
      params = netsparker_params_map(vuln)

      proof  = ''

      if vuln['info'] and vuln['info'].length > 0
        proof << vuln['info'].map{|x| "#{x[0]}: #{x[1]}\n" }.join + "\n"
      end

      if proof.empty?
        if body
          proof << body + "\n"
        else
          proof << vuln['response'].to_s + "\n"
        end
      end

      if params.empty? and pname
        params = [[pname, vuln['vparam_name'].to_s]]
      end

      info = {
        # XXX: There is a :request attr in the model, but report_web_vuln
        # doesn't seem to know about it, so this gets ignored.
        #:request  => vuln['request'],
        :path        => uri.path,
        :query       => uri.query,
        :method      => method,
        :params      => params,
        :pname       => pname.to_s,
        :proof       => proof,
        :risk        => details[:risk],
        :name        => details[:name],
        :blame       => details[:blame],
        :category    => details[:category],
        :description => details[:description],
        :confidence  => details[:confidence],
        :task        => args[:task]
      }
      info.merge!(data)

      next if vuln['type'].to_s.empty?

      report_web_vuln(info)
      yield(:web_vuln, url) if block
    end

    # We throw interrupts in our parser when the job is hopeless
    begin
      REXML::Document.parse_stream(data, parser)
    rescue ::Interrupt => e
      wlog("The netsparker_xml_import() job was interrupted: #{e}")
    end
  end

  # Process a NetSparker XML file
  def import_netsparker_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_netsparker_xml(args.merge(:data => data))
  end

  def import_nexpose_noko_stream(args, &block)
    if block
      doc = Rex::Parser::NexposeSimpleDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::NexposeSimpleDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_nexpose_raw_noko_stream(args, &block)
    if block
      doc = Rex::Parser::NexposeRawDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::NexposeRawDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_nexpose_rawxml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_nexpose_raw_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_nexpose_raw_noko_stream(noko_args)
      end
      return true
    end
    data = args[:data]

    # Use a stream parser instead of a tree parser so we can deal with
    # huge results files without running out of memory.
    parser = Rex::Parser::NexposeXMLStreamParser.new

    # Since all the Refs have to be in the database before we can use them
    # in a Vuln, we store all the hosts until we finish parsing and only
    # then put everything in the database.  This is memory-intensive for
    # large files, but should be much less so than a tree parser.
    #
    # This method is also considerably faster than parsing through the tree
    # looking for references every time we hit a vuln.
    hosts = []
    vulns = []

    # The callback merely populates our in-memory table of hosts and vulns
    parser.callback = Proc.new { |type, value|
      case type
      when :host
        # XXX: Blacklist should be checked here instead of saving a
        # host we're just going to throw away later
        hosts.push(value)
      when :vuln
        value["id"] = value["id"].downcase if value["id"]
        vulns.push(value)
      end
    }

    REXML::Document.parse_stream(data, parser)

    vuln_refs = nexpose_refs_to_struct(vulns)
    hosts.each do |host|
      if bl.include? host["addr"]
        next
      else
        yield(:address,host["addr"]) if block
      end
      nexpose_host_from_rawxml(host, vuln_refs, wspace)
    end
  end

  #
  # Nexpose Raw XML
  #
  def import_nexpose_rawxml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nexpose_rawxml(args.merge(:data => data))
  end

  def import_nexpose_simplexml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_nexpose_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_nexpose_noko_stream(noko_args)
      end
      return true
    end
    data = args[:data]

    doc = rexmlify(data)
    doc.elements.each('/NeXposeSimpleXML/devices/device') do |dev|
      addr = dev.attributes['address'].to_s
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      fprint = {}

      dev.elements.each('fingerprint/description') do |str|
        fprint[:desc] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/vendor') do |str|
        fprint[:vendor] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/family') do |str|
        fprint[:family] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/product') do |str|
        fprint[:product] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/version') do |str|
        fprint[:version] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/architecture') do |str|
        fprint[:arch] = str.text.to_s.upcase.strip
      end

      conf = {
        :workspace => wspace,
        :host      => addr,
        :state     => Msf::HostState::Alive,
        :task      => args[:task]
      }

      host = report_host(conf)
      report_import_note(wspace, host)

      report_note(
        :workspace => wspace,
        :host      => host,
        :type      => 'host.os.nexpose_fingerprint',
        :data      => fprint,
        :task      => args[:task]
      )

      # Load vulnerabilities not associated with a service
      dev.elements.each('vulnerabilities/vulnerability') do |vuln|
        vid  = vuln.attributes['id'].to_s.downcase
        refs = process_nexpose_data_sxml_refs(vuln)
        next if not refs
        report_vuln(
          :workspace => wspace,
          :host      => host,
          :name      => 'NEXPOSE-' + vid,
          :info      => vid,
          :refs      => refs,
          :task      => args[:task]
        )
      end

      # Load the services
      dev.elements.each('services/service') do |svc|
        sname = svc.attributes['name'].to_s
        sprot = svc.attributes['protocol'].to_s.downcase
        sport = svc.attributes['port'].to_s.to_i
        next if sport == 0

        name = sname.split('(')[0].strip
        info = ''

        svc.elements.each('fingerprint/description') do |str|
          info = str.text.to_s.strip
        end

        if(sname.downcase != '<unknown>')
          report_service(
              :workspace => wspace,
              :host      => host,
              :proto     => sprot,
              :port      => sport,
              :name      => name,
              :info      => info,
              :task      => args[:task]
          )
        else
          report_service(
              :workspace => wspace,
              :host      => host,
              :proto     => sprot,
              :port      => sport,
              :info      => info,
              :task      => args[:task]
          )
        end

        # Load vulnerabilities associated with this service
        svc.elements.each('vulnerabilities/vulnerability') do |vuln|
          vid  = vuln.attributes['id'].to_s.downcase
          refs = process_nexpose_data_sxml_refs(vuln)
          next if not refs
          report_vuln(
              :workspace => wspace,
              :host      => host,
              :port      => sport,
              :proto     => sprot,
              :name      => 'NEXPOSE-' + vid,
              :info      => vid,
              :refs      => refs,
              :task      => args[:task]
          )
        end
      end
    end
  end

  #
  # Nexpose Simple XML
  #
  # XXX At some point we'll want to make this a stream parser for dealing
  # with large results files
  #
  def import_nexpose_simplexml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nexpose_simplexml(args.merge(:data => data))
  end

  #
  # Imports Nikto scan data from -Format xml as notes.
  #
  def import_nikto_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    doc = rexmlify(data)
    doc.elements.each do |f|
      f.elements.each('scandetails') do |host|
        # Get host information
        addr = host.attributes['targetip']
        next if not addr
        if bl.include? addr
          next
        else
          yield(:address,addr) if block
        end
        # Get service information
        port = host.attributes['targetport']
        next if port.to_i == 0
        uri = URI.parse(host.attributes['sitename']) rescue nil
        next unless uri and uri.scheme
        # Collect and report scan descriptions.
        host.elements.each do |item|
          if item.elements['description']
            desc_text = item.elements['description'].text
            next if desc_text.nil? or desc_text.empty?
            desc_data = {
                :workspace => wspace,
                :host      => addr,
                :type      => "service.nikto.scan.description",
                :data      => desc_text,
                :proto     => "tcp",
                :port      => port.to_i,
                :sname     => uri.scheme,
                :update    => :unique_data,
                :task      => args[:task]
            }
            # Always report it as a note.
            report_note(desc_data)
            # Sometimes report it as a vuln, too.
            # XXX: There's a Vuln.info field but nothing reads from it? See Bug #5837
            if item.attributes['osvdbid'].to_i != 0
              desc_data[:refs] = ["OSVDB-#{item.attributes['osvdbid']}"]
              desc_data[:name] = "NIKTO-#{item.attributes['id']}"
              desc_data.delete(:data)
              desc_data.delete(:type)
              desc_data.delete(:update)
              report_vuln(desc_data)
            end
          end
        end
      end
    end
  end

  def import_nmap_noko_stream(args, &block)
    if block
      doc = Rex::Parser::NmapDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::NmapDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  # If you have Nokogiri installed, you'll be shunted over to
  # that. Otherwise, you'll hit the old NmapXMLStreamParser.
  def import_nmap_xml(args={}, &block)
    return nil if args[:data].nil? or args[:data].empty?
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    if Rex::Parser.nokogiri_loaded
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, "Nokogiri v#{::Nokogiri::VERSION}")
        import_nmap_noko_stream(noko_args) {|type, data| yield type,data }
      else
        import_nmap_noko_stream(noko_args)
      end
      return true
    end

    # XXX: Legacy nmap xml parser starts here.

    fix_services = args[:fix_services]
    data = args[:data]

    # Use a stream parser instead of a tree parser so we can deal with
    # huge results files without running out of memory.
    parser = Rex::Parser::NmapXMLStreamParser.new
    yield(:parser, parser.class.name) if block

    # Whenever the parser pulls a host out of the nmap results, store
    # it, along with any associated services, in the database.
    parser.on_found_host = Proc.new { |h|
      hobj = nil
      data = {:workspace => wspace}
      if (h["addrs"].has_key?("ipv4"))
        addr = h["addrs"]["ipv4"]
      elsif (h["addrs"].has_key?("ipv6"))
        addr = h["addrs"]["ipv6"]
      else
        # Can't report it if it doesn't have an IP
        raise RuntimeError, "At least one IPv4 or IPv6 address is required"
      end
      next if bl.include? addr
      data[:host] = addr
      if (h["addrs"].has_key?("mac"))
        data[:mac] = h["addrs"]["mac"]
      end
      data[:state] = (h["status"] == "up") ? Msf::HostState::Alive : Msf::HostState::Dead
      data[:task] = args[:task]

      if ( h["reverse_dns"] )
        data[:name] = h["reverse_dns"]
      end

      # Only report alive hosts with ports to speak of.
      if(data[:state] != Msf::HostState::Dead)
        if h["ports"].size > 0
          if fix_services
            port_states = h["ports"].map {|p| p["state"]}.reject {|p| p == "filtered"}
            next if port_states.compact.empty?
          end
          yield(:address,data[:host]) if block
          hobj = report_host(data)
          report_import_note(wspace,hobj)
        end
      end

      if( h["os_vendor"] )
        note = {
          :workspace => wspace,
          :host => hobj || addr,
          :type => 'host.os.nmap_fingerprint',
          :task => args[:task],
          :data => {
            :os_vendor   => h["os_vendor"],
            :os_family   => h["os_family"],
            :os_version  => h["os_version"],
            :os_accuracy => h["os_accuracy"]
          }
        }

        if(h["os_match"])
          note[:data][:os_match] = h['os_match']
        end

        report_note(note)
      end

      if (h["last_boot"])
        report_note(
          :workspace => wspace,
          :host => hobj || addr,
          :type => 'host.last_boot',
          :task => args[:task],
          :data => {
            :time => h["last_boot"]
          }
        )
      end

      if (h["trace"])
        hops = []
        h["trace"]["hops"].each do |hop|
          hops << {
            "ttl"     => hop["ttl"].to_i,
            "address" => hop["ipaddr"].to_s,
            "rtt"     => hop["rtt"].to_f,
            "name"    => hop["host"].to_s
          }
        end
        report_note(
          :workspace => wspace,
          :host => hobj || addr,
          :type => 'host.nmap.traceroute',
          :task => args[:task],
          :data => {
            'port'  => h["trace"]["port"].to_i,
            'proto' => h["trace"]["proto"].to_s,
            'hops'  => hops
          }
        )
      end


      # Put all the ports, regardless of state, into the db.
      h["ports"].each { |p|
        # Localhost port results are pretty unreliable -- if it's
        # unknown, it's no good (possibly Windows-only)
        if (
          p["state"] == "unknown" &&
          h["status_reason"] == "localhost-response"
        )
          next
        end
        extra = ""
        extra << p["product"]   + " " if p["product"]
        extra << p["version"]   + " " if p["version"]
        extra << p["extrainfo"] + " " if p["extrainfo"]

        data = {}
        data[:workspace] = wspace
        if fix_services
          data[:proto] = nmap_msf_service_map(p["protocol"])
        else
          data[:proto] = p["protocol"].downcase
        end
        data[:port]  = p["portid"].to_i
        data[:state] = p["state"]
        data[:host]  = hobj || addr
        data[:info]  = extra if not extra.empty?
        data[:task]  = args[:task]
        if p["name"] != "unknown"
          data[:name] = p["name"]
        end
        report_service(data)
      }
      #Parse the scripts output
      if h["scripts"]
        h["scripts"].each do |key,val|
          if key == "smb-check-vulns"
            if val =~ /MS08-067: VULNERABLE/
              vuln_info = {
                :workspace => wspace,
                :task => args[:task],
                :host =>  hobj || addr,
                :port => 445,
                :proto => 'tcp',
                :name => 'MS08-067',
                :info => 'Microsoft Windows Server Service Crafted RPC Request Handling Unspecified Remote Code Execution',
                :refs =>['CVE-2008-4250',
                  'BID-31874',
                  'OSVDB-49243',
                  'CWE-94',
                  'MSFT-MS08-067',
                  'MSF-Microsoft Server Service Relative Path Stack Corruption',
                  'NSS-34476']
              }
              report_vuln(vuln_info)
            end
            if val =~ /MS06-025: VULNERABLE/
              vuln_info = {
                :workspace => wspace,
                :task => args[:task],
                :host =>  hobj || addr,
                :port => 445,
                :proto => 'tcp',
                :name => 'MS06-025',
                :info => 'Vulnerability in Routing and Remote Access Could Allow Remote Code Execution',
                :refs =>['CVE-2006-2370',
                  'CVE-2006-2371',
                  'BID-18325',
                  'BID-18358',
                  'BID-18424',
                  'OSVDB-26436',
                  'OSVDB-26437',
                  'MSFT-MS06-025',
                  'MSF-Microsoft RRAS Service RASMAN Registry Overflow',
                  'NSS-21689']
              }
              report_vuln(vuln_info)
            end
            # This one has NOT been  Tested , remove this comment if confirmed working
            if val =~ /MS07-029: VULNERABLE/
              vuln_info = {
                :workspace => wspace,
                :task => args[:task],
                :host =>  hobj || addr,
                :port => 445,
                :proto => 'tcp',
                :name => 'MS07-029',
                :info => 'Vulnerability in Windows DNS RPC Interface Could Allow Remote Code Execution',
                # Add more refs based on nessus/nexpose .. results
                :refs =>['CVE-2007-1748',
                  'OSVDB-34100',
                  'MSF-Microsoft DNS RPC Service extractQuotedChar()',
                  'NSS-25168']
              }
              report_vuln(vuln_info)
            end
          end
        end
      end
    }

    # XXX: Legacy nmap xml parser ends here.

    REXML::Document.parse_stream(data, parser)
  end

  #
  # Import Nmap's -oX xml output
  #
  def import_nmap_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nmap_xml(args.merge(:data => data))
  end

  def import_openvas_new_xml(args={}, &block)
    if block
      doc = Rex::Parser::OpenVASDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::OpenVASDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_openvas_new_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_wapiti_xml(args.merge(:data => data))
  end

  # Do all the single packet analysis we can while churning through the pcap
  # the first time. Multiple packet inspection will come later, where we can
  # do stream analysis, compare requests and responses, etc.
  def inspect_single_packet(pkt,wspace,args)
    if pkt.is_tcp? or pkt.is_udp?
      inspect_single_packet_http(pkt,wspace,args)
    end
  end

  # Checks for packets that are headed towards port 80, are tcp, contain an HTTP/1.0
  # line, contains an Authorization line, contains a b64-encoded credential, and
  # extracts it. Reports this credential and solidifies the service as HTTP.
  def inspect_single_packet_http(pkt,wspace,args)
    task = args.fetch(:task, nil)
    # First, check the server side (data from port 80).
    if pkt.is_tcp? and pkt.tcp_src == 80 and !pkt.payload.nil? and !pkt.payload.empty?
      if pkt.payload =~ /^HTTP\x2f1\x2e[01]/n
        http_server_match = pkt.payload.match(/\nServer:\s+([^\r\n]+)[\r\n]/n)
        if http_server_match.kind_of?(MatchData) and http_server_match[1]
          report_service(
              :workspace => wspace,
              :host      => pkt.ip_saddr,
              :port      => pkt.tcp_src,
              :proto     => "tcp",
              :name      => "http",
              :info      => http_server_match[1],
              :state     => Msf::ServiceState::Open,
              :task      => task
          )
          # That's all we want to know from this service.
          return :something_significant
        end
      end
    end

    # Next, check the client side (data to port 80)
    if pkt.is_tcp? and pkt.tcp_dst == 80 and !pkt.payload.nil? and !pkt.payload.empty?
      if pkt.payload.match(/[\x00-\x20]HTTP\x2f1\x2e[10]/n)
        auth_match = pkt.payload.match(/\nAuthorization:\s+Basic\s+([A-Za-z0-9=\x2b]+)/n)
        if auth_match.kind_of?(MatchData) and auth_match[1]
          b64_cred = auth_match[1]
        else
          return false
        end
        # If we're this far, we can surmise that at least the client is a web browser,
        # he thinks the server is HTTP and he just made an authentication attempt. At
        # this point, we'll just believe everything the packet says -- validation ought
        # to come later.
        user,pass = b64_cred.unpack("m*").first.split(/:/,2)
        report_service(
            :workspace => wspace,
            :host      => pkt.ip_daddr,
            :port      => pkt.tcp_dst,
            :proto     => "tcp",
            :name      => "http",
            :task      => task
        )

        service_data = {
            address: pkt.ip_daddr,
            port: pkt.tcp_dst,
            service_name: 'http',
            protocol: 'tcp',
            workspace_id: wspace.id
        }
        service_data[:task_id] = task.id if task

        filename = args[:filename]

        credential_data = {
            origin_type: :import,
            private_data: pass,
            private_type: :password,
            username: user,
            filename: filename
        }
        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
            core: credential_core,
            status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)

        create_credential_login(login_data)

        # That's all we want to know from this service.
        return :something_significant
      end
    end
  end

  def import_wapiti_xml(args={}, &block)
    if block
      doc = Rex::Parser::WapitiDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::WapitiDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_wapiti_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_wapiti_xml(args.merge(:data => data))
  end

  #
  # Of course they had to change the nessus format.
  #
  def import_openvas_xml(args={}, &block)
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    raise DBImportError.new("No OpenVAS XML support. Please submit a patch to msfdev[at]metasploit.com")
  end

  def import_outpost24_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::Outpost24Document.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::Outpost24Document.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_outpost24_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_outpost24_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_outpost24_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  # @param report [REXML::Element] to be imported
  # @param args [Hash]
  # @param base_dir [String]
  def import_report(report, args, base_dir)
    tmp = args[:ifd][:zip_tmp]
    report_info = {}

    report.elements.each do |e|
      node_name  = e.name
      node_value = e.text

      # These need to be converted back to arrays:
      array_attrs = %w|addresses file-formats options sections|
      if array_attrs.member? node_name
        node_value = JSON.parse(node_value)
      end
      # Don't restore these values:
      skip_nodes = %w|id workspace-id artifacts|
      next if skip_nodes.member? node_name

      report_info[node_name.parameterize.underscore.to_sym] = node_value
    end
    # Use current workspace
    report_info[:workspace_id] = args[:wspace].id

    # Create report, need new ID to record artifacts
    report_id = report_report(report_info)

    # Handle artifacts
    report.elements['artifacts'].elements.each do |artifact|
      artifact_opts = {}
      artifact.elements.each do |attr|
        skip_nodes = %w|id accessed-at|
        next if skip_nodes.member? attr.name

        symboled_attr = attr.name.parameterize.underscore.to_sym
        artifact_opts[symboled_attr] = attr.text
      end
      # Use new Report as parent
      artifact_opts[:report_id] = report_id
      # Update to full path
      artifact_opts[:file_path].gsub!(/^\./, tmp)

      report_artifact(artifact_opts)
    end
  end

  # Process Retina XML
  def import_retina_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    msg =  "Warning: The Retina XML format does not associate vulnerabilities with the\n"
    msg << "specific service on which they were found.\n"
    msg << "This makes it impossible to correlate exploits to discovered vulnerabilities\n"
    msg << "in a reliable fashion."

    yield(:warning,msg) if block

    parser = Rex::Parser::RetinaXMLStreamParser.new
    parser.on_found_host = Proc.new do |host|
      hobj = nil
      data = {
        :workspace => wspace,
        :task      => args[:task]
      }
      addr = host['address']
      next if not addr

      next if bl.include? addr
      data[:host] = addr

      if host['mac']
        data[:mac] = host['mac']
      end

      data[:state] = Msf::HostState::Alive

      if host['hostname']
        data[:name] = host['hostname']
      end

      if host['netbios']
        data[:name] = host['netbios']
      end

      yield(:address, data[:host]) if block

      # Import Host
      hobj = report_host(data)
      report_import_note(wspace, hobj)

      # Import OS fingerprint
      if host["os"]
        note = {
            :workspace => wspace,
            :host      => addr,
            :type      => 'host.os.retina_fingerprint',
            :task      => args[:task],
            :data      => {
                :os => host["os"]
            }
        }
        report_note(note)
      end

      # Import vulnerabilities
      host['vulns'].each do |vuln|
        refs = vuln['refs'].map{|v| v.join("-")}
        refs << "RETINA-#{vuln['rthid']}" if vuln['rthid']

        vuln_info = {
            :workspace => wspace,
            :host      => addr,
            :name      => vuln['name'],
            :info      => vuln['description'],
            :refs      => refs,
            :task      => args[:task]
        }

        report_vuln(vuln_info)
      end
    end

    REXML::Document.parse_stream(data, parser)
  end

  # Process a Retina XML file
  def import_retina_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_retina_xml(args.merge(:data => data))
  end

  def import_spiceworks_csv(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    CSV.parse(data) do |row|
      next unless (["Name", "Manufacturer", "Device Type"] & row).empty? #header
      name = row[0]
      manufacturer = row[1]
      device = row[2]
      model = row[3]
      ip = row[4]
      serialno = row[5]
      location = row[6]
      os = row[7]

      next unless ip
      next if bl.include? ip

      conf = {
      :workspace => wspace,
      :host      => ip,
      :name      => name,
      :task      => args[:task]
      }


      if os
        report_note(
          :workspace => wspace,
          :task => args[:task],
          :host => ip,
          :type => 'host.os.spiceworks_fingerprint',
          :data => {
            :os => os.to_s.strip
          }
        )
      end

      info = []
      info << "Serial Number: #{serialno}" unless (serialno.blank? or serialno == name)
      info << "Location: #{location}" unless location.blank?
      conf[:info] = info.join(", ") unless info.empty?

      host = report_host(conf)
      report_import_note(wspace, host)
    end
  end

  # Handles timestamps from Metasploit Express/Pro imports.
  def msf_import_timestamps(opts,obj)
    obj.created_at = opts["created_at"] if opts["created_at"]
    obj.created_at = opts[:created_at] if opts[:created_at]
    obj.updated_at = opts["updated_at"] ? opts["updated_at"] : obj.created_at
    obj.updated_at = opts[:updated_at] ? opts[:updated_at] : obj.created_at
    return obj
  end

  def netsparker_method_map(vuln)
    case vuln['vparam_type']
    when "FullQueryString"
      "GET"
    when "Querystring"
      "GET"
    when "Post"
      "POST"
    when "RawUrlInjection"
      "GET"
    else
      "GET"
    end
  end

  def netsparker_params_map(vuln)
    []
  end

  def netsparker_pname_map(vuln)
    case vuln['vparam_name']
    when "URI-BASED", "Query Based"
      "PATH"
    else
      vuln['vparam_name']
    end
  end

  def netsparker_vulnerability_map(vuln)
    res = {
      :risk => 1,
      :name  => 'Information Disclosure',
      :blame => 'System Administrator',
      :category => 'info',
      :description => "This is an information leak",
      :confidence => 100
    }

    # Risk is a value from 1-5 indicating the severity of the issue
    #	Examples: 1, 4, 5

    # Name is a descriptive name for this vulnerability.
    #	Examples: XSS, ReflectiveXSS, PersistentXSS

    # Blame indicates who is at fault for the vulnerability
    #	Examples: App Developer, Server Developer, System Administrator

    # Category indicates the general class of vulnerability
    #	Examples: info, xss, sql, rfi, lfi, cmd

    # Description is a textual summary of the vulnerability
    #	Examples: "A reflective cross-site scripting attack"
    #             "The web server leaks the internal IP address"
    #             "The cookie is not set to HTTP-only"

    #
    # Confidence is a value from 1 to 100 indicating how confident the
    # software is that the results are valid.
    #	Examples: 100, 90, 75, 15, 10, 0

    case vuln['type'].to_s
    when "ApacheDirectoryListing"
      res = {
        :risk => 1,
        :name  => 'Directory Listing',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "ApacheMultiViewsEnabled"
      res = {
        :risk => 1,
        :name  => 'Apache MultiViews Enabled',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "ApacheVersion"
      res = {
        :risk => 1,
        :name  => 'Web Server Version',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PHPVersion"
      res = {
        :risk => 1,
        :name  => 'PHP Module Version',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "AutoCompleteEnabled"
      res = {
        :risk => 1,
        :name  => 'Form AutoComplete Enabled',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "CookieNotMarkedAsHttpOnly"
      res = {
        :risk => 1,
        :name  => 'Cookie Not HttpOnly',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "EmailDisclosure"
      res = {
        :risk => 1,
        :name  => 'Email Address Disclosure',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "ForbiddenResource"
      res = {
        :risk => 1,
        :name  => 'Forbidden Resource',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "FileUploadFound"
      res = {
        :risk => 1,
        :name  => 'File Upload Form',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PasswordOverHTTP"
      res = {
        :risk => 2,
        :name  => 'Password Over HTTP',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "MySQL5Identified"
      res = {
        :risk => 1,
        :name  => 'MySQL 5 Identified',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PossibleInternalWindowsPathLeakage"
      res = {
        :risk => 1,
        :name  => 'Path Leakage - Windows',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PossibleInternalUnixPathLeakage"
      res = {
        :risk => 1,
        :name  => 'Path Leakage - Unix',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PossibleXSS", "LowPossibilityPermanentXSS", "XSS", "PermanentXSS"
      conf = 100
      conf = 25  if vuln['type'].to_s == "LowPossibilityPermanentXSS"
      conf = 50  if vuln['type'].to_s == "PossibleXSS"
      res = {
        :risk => 3,
        :name  => 'Cross-Site Scripting',
        :blame => 'App Developer',
        :category => 'xss',
        :description => "",
        :confidence => conf
      }

    when "ConfirmedBlindSQLInjection", "ConfirmedSQLInjection", "HighlyPossibleSqlInjection", "DatabaseErrorMessages"
      conf = 100
      conf = 90  if vuln['type'].to_s == "HighlyPossibleSqlInjection"
      conf = 25  if vuln['type'].to_s == "DatabaseErrorMessages"
      res = {
        :risk => 5,
        :name  => 'SQL Injection',
        :blame => 'App Developer',
        :category => 'sql',
        :description => "",
        :confidence => conf
      }
    else
    conf = 100
    res = {
      :risk => 1,
      :name  => vuln['type'].to_s,
      :blame => 'App Developer',
      :category => 'info',
      :description => "",
      :confidence => conf
    }
    end

    res
  end

  # Takes a Host object, an array of vuln structs (generated by nexpose_refs_to_struct()),
  # and a workspace, and reports the vulns on that host.
  def nexpose_host_from_rawxml(h, vstructs, wspace,task=nil)
    hobj = nil
    data = {:workspace => wspace}
    if h["addr"]
      addr = h["addr"]
    else
      # Can't report it if it doesn't have an IP
      return
    end
    data[:host] = addr
    if (h["hardware-address"])
      # Put colons between each octet of the MAC address
      data[:mac] = h["hardware-address"].gsub(':', '').scan(/../).join(':')
    end
    data[:state] = (h["status"] == "alive") ? Msf::HostState::Alive : Msf::HostState::Dead

    # Since we only have one name field per host in the database, just
    # take the first one.
    if (h["names"] and h["names"].first)
      data[:name] = h["names"].first
    end

    if (data[:state] != Msf::HostState::Dead)
      hobj = report_host(data)
      report_import_note(wspace, hobj)
    end

    if h["notes"]
      note = {
          :workspace => wspace,
          :host      => (hobj || addr),
          :type      => "host.vuln.nexpose_keys",
          :data      => {},
          :mode      => :unique_data,
          :task      => task
      }
      h["notes"].each do |v,k|
        note[:data][v] ||= []
        next if note[:data][v].include? k
        note[:data][v] << k
      end
      report_note(note)
    end

    if h["os_family"]
      note = {
          :workspace => wspace,
          :host      => hobj || addr,
          :type      => 'host.os.nexpose_fingerprint',
          :task      => task,
          :data      => {
              :family    => h["os_family"],
              :certainty => h["os_certainty"]
          }
      }
      note[:data][:vendor]  = h["os_vendor"]  if h["os_vendor"]
      note[:data][:product] = h["os_product"] if h["os_product"]
      note[:data][:version] = h["os_version"] if h["os_version"]
      note[:data][:arch]    = h["arch"]       if h["arch"]

      report_note(note)
    end

    h["endpoints"].each { |p|
      extra = ""
      extra << p["product"] + " " if p["product"]
      extra << p["version"] + " " if p["version"]

      # Skip port-0 endpoints
      next if p["port"].to_i == 0

      # XXX This should probably be handled in a more standard way
      # extra << "(" + p["certainty"] + " certainty) " if p["certainty"]

      data             = {}
      data[:workspace] = wspace
      data[:proto]     = p["protocol"].downcase
      data[:port]      = p["port"].to_i
      data[:state]     = p["status"]
      data[:host]      = hobj || addr
      data[:info]      = extra if not extra.empty?
      data[:task]      = task
      if p["name"] != "<unknown>"
        data[:name] = p["name"]
      end
      report_service(data)
    }

    h["vulns"].each_pair { |k,v|

      next if v["status"] !~ /^vulnerable/
      vstruct = vstructs.select {|vs| vs.id.to_s.downcase == v["id"].to_s.downcase}.first
      next unless vstruct
      data             = {}
      data[:workspace] = wspace
      data[:host]      = hobj || addr
      data[:proto]     = v["protocol"].downcase if v["protocol"]
      data[:port]      = v["port"].to_i if v["port"]
      data[:name]      = "NEXPOSE-" + v["id"]
      data[:info]      = vstruct.title
      data[:refs]      = vstruct.refs
      data[:task]      = task
      report_vuln(data)
    }
  end

  #
  # Takes an array of vuln hashes, as returned by the NeXpose rawxml stream
  # parser, like:
  #   [
  #     {"id"=>"winreg-notes-protocol-handler", severity="8", "refs"=>[{"source"=>"BID", "value"=>"10600"}, ...]}
  #     {"id"=>"windows-zotob-c", severity="8", "refs"=>[{"source"=>"BID", "value"=>"14513"}, ...]}
  #   ]
  # and transforms it into a struct, containing :id, :refs, :title, and :severity
  #
  # Other attributes can be added later, as needed.
  def nexpose_refs_to_struct(vulns)
    ret = []
    vulns.each do |vuln|
      next if ret.map {|v| v.id}.include? vuln["id"]
      vstruct = Struct.new(:id, :refs, :title, :severity).new
      vstruct.id = vuln["id"]
      vstruct.title = vuln["title"]
      vstruct.severity = vuln["severity"]
      vstruct.refs = []
      vuln["refs"].each do |ref|
        if ref['source'] == 'BID'
          vstruct.refs.push('BID-' + ref["value"])
        elsif ref['source'] == 'CVE'
          # value is CVE-$ID
          vstruct.refs.push(ref["value"])
        elsif ref['source'] == 'MS'
          vstruct.refs.push('MSB-' + ref["value"])
        elsif ref['source'] == 'URL'
          vstruct.refs.push('URL-' + ref["value"])
        end
      end
      ret.push vstruct
    end
    return ret
  end

  # Convert the string "NULL" to actual nil
  def nils_for_nulls(str)
    str == "NULL" ? nil : str
  end

  def nmap_msf_service_map(proto)
    service_name_map(proto)
  end

  def report_import_note(wspace,addr)
    if @import_filedata.kind_of?(Hash) && @import_filedata[:filename] && @import_filedata[:filename] !~ /msfe-nmap[0-9]{8}/
    report_note(
      :workspace => wspace,
      :host => addr,
      :type => 'host.imported',
      :data => @import_filedata.merge(:time=> Time.now.utc)
    )
    end
  end

  # Returns a REXML::Document from the given data.
  def rexmlify(data)
    if data.kind_of?(REXML::Document)
      return data
    else
      # Make an attempt to recover from a REXML import fail, since
      # it's better than dying outright.
      begin
        return REXML::Document.new(data)
      rescue REXML::ParseException => e
        dlog("REXML error: Badly formatted XML, attempting to recover. Error was: #{e.inspect}")
        return REXML::Document.new(data.gsub(/([\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xff])/n){ |x| "\\x%.2x" % x.unpack("C*")[0] })
      end
    end
  end

  #
  # This method normalizes an incoming service name to one of the
  # the standard ones recognized by metasploit
  #
  def service_name_map(proto)
    return proto unless proto.kind_of? String
    case proto.downcase
    when "msrpc", "nfs-or-iis", "dce endpoint resolution"
      "dcerpc"
    when "ms-sql-s", "tds"
      "mssql"
    when "ms-sql-m","microsoft sql monitor"
      "mssql-m"
    when "postgresql";                  "postgres"
    when "http-proxy";                  "http"
    when "iiimsf";                      "db2"
    when "oracle-tns";                  "oracle"
    when "quickbooksrds";               "metasploit"
    when "microsoft remote display protocol"
      "rdp"
    when "vmware authentication daemon"
      "vmauthd"
    when "netbios-ns", "cifs name service"
      "netbios"
    when "netbios-ssn", "microsoft-ds", "cifs"
      "smb"
    when "remote shell"
      "shell"
    when "remote login"
      "login"
    when "nfs lockd"
      "lockd"
    when "hp jetdirect"
      "jetdirect"
    when "dhcp server"
      "dhcp"
    when /^dns-(udp|tcp)$/;             "dns"
    when /^dce[\s+]rpc$/;               "dcerpc"
    else
      proto.downcase.gsub(/\s*\(.*/, '')   # "service (some service)"
    end
  end

  def unserialize_object(xml_elem, allow_yaml = false)
    return nil unless xml_elem
    string = xml_elem.text.to_s.strip
    return string unless string.is_a?(String)
    return nil if (string.empty? || string.nil?)

    begin
      # Validate that it is properly formed base64 first
      if string.gsub(/\s+/, '') =~ /^([a-z0-9A-Z\+\/=]+)$/
        Marshal.load($1.unpack("m")[0])
      else
        if allow_yaml
          begin
            YAML.load(string)
          rescue
            dlog("Badly formatted YAML: '#{string}'")
            string
          end
        else
          string
        end
      end
    rescue ::Exception => e
      if allow_yaml
        YAML.load(string) rescue string
      else
        string
      end
    end
  end

  # Boils down the validate_import_file to a boolean
  def validate_import_file(data)
    begin
      import_filetype_detect(data)
    rescue DBImportError
      return false
    end
    return true
  end

  protected

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

  def process_nexpose_data_sxml_refs(vuln)
    refs = []
    vid = vuln.attributes['id'].to_s.downcase
    vry = vuln.attributes['resultCode'].to_s.upcase

    # Only process vuln-exploitable and vuln-version statuses
    return if vry !~ /^V[VE]$/

    refs = []
    vuln.elements.each('id') do |ref|
      rtyp = ref.attributes['type'].to_s.upcase
      rval = ref.text.to_s.strip
      case rtyp
      when 'CVE'
        refs << rval.gsub('CAN', 'CVE')
      when 'MS' # obsolete?
        refs << "MSB-MS-#{rval}"
      else
        refs << "#{rtyp}-#{rval}"
      end
    end

    refs << "NEXPOSE-#{vid}"
    refs
  end
end