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
  autoload :Burp, 'msf/core/db_manager/import/burp'
  autoload :CI, 'msf/core/db_manager/import/ci'
  autoload :Foundstone, 'msf/core/db_manager/import/foundstone'
  autoload :FusionVM, 'msf/core/db_manager/import/fusion_vm'
  autoload :IP360, 'msf/core/db_manager/import/ip360'
  autoload :IPList, 'msf/core/db_manager/import/ip_list'
  autoload :Libpcap, 'msf/core/db_manager/import/libpcap'
  autoload :MBSA, 'msf/core/db_manager/import/mbsa'
  autoload :MetasploitFramework, 'msf/core/db_manager/import/metasploit_framework'
  autoload :Nessus, 'msf/core/db_manager/import/nessus'
  autoload :Netsparker, 'msf/core/db_manager/import/netsparker'
  autoload :Nexpose, 'msf/core/db_manager/import/nexpose'
  autoload :Qualys, 'msf/core/db_manager/import/qualys'

  include Msf::DBManager::Import::Acunetix
  include Msf::DBManager::Import::Amap
  include Msf::DBManager::Import::Appscan
  include Msf::DBManager::Import::Burp
  include Msf::DBManager::Import::CI
  include Msf::DBManager::Import::Foundstone
  include Msf::DBManager::Import::FusionVM
  include Msf::DBManager::Import::IP360
  include Msf::DBManager::Import::IPList
  include Msf::DBManager::Import::Libpcap
  include Msf::DBManager::Import::MBSA
  include Msf::DBManager::Import::MetasploitFramework
  include Msf::DBManager::Import::Nessus
  include Msf::DBManager::Import::Netsparker
  include Msf::DBManager::Import::Nexpose
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

  def import_nexpose_noko_stream(args, &block)
    if block
      doc = Rex::Parser::NexposeSimpleDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::NexposeSimpleDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
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