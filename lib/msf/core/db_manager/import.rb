module Msf::DBManager::Import
  require 'msf/core/db_manager/import/acunetix'
  include Msf::DBManager::Import::Acunetix

  require 'msf/core/db_manager/import/amap'
  include Msf::DBManager::Import::Amap

  require 'msf/core/db_manager/import/app_scan'
  include Msf::DBManager::Import::AppScan

  require 'msf/core/db_manager/import/burp'
  include Msf::DBManager::Import::Burp

  require 'msf/core/db_manager/import/ci'
  include Msf::DBManager::Import::CI

  require 'msf/core/db_manager/import/foundstone'
  include Msf::DBManager::Import::Foundstone

  require 'msf/core/db_manager/import/fusion_vm'
  include Msf::DBManager::Import::FusionVM

  require 'msf/core/db_manager/import/ip360'
  include Msf::DBManager::Import::IP360

  require 'msf/core/db_manager/import/ip_list'
  include Msf::DBManager::Import::IPList

  require 'msf/core/db_manager/import/libpcap'
  include Msf::DBManager::Import::Libpcap

  require 'msf/core/db_manager/import/mbsa'
  include Msf::DBManager::Import::MBSA

  require 'msf/core/db_manager/import/metasploit_framework'
  include Msf::DBManager::Import::MetasploitFramework

  require 'msf/core/db_manager/import/nessus'
  include Msf::DBManager::Import::Nessus

  require 'msf/core/db_manager/import/netsparker'
  include Msf::DBManager::Import::Netsparker

  require 'msf/core/db_manager/import/nexpose'
  include Msf::DBManager::Import::Nexpose

  require 'msf/core/db_manager/import/nikto'
  include Msf::DBManager::Import::Nikto

  require 'msf/core/db_manager/import/nmap'
  include Msf::DBManager::Import::Nmap

  require 'msf/core/db_manager/import/open_vas'
  include Msf::DBManager::Import::OpenVAS

  require 'msf/core/db_manager/import/qualys'
  include Msf::DBManager::Import::Qualys

  require 'msf/core/db_manager/import/retina'
  include Msf::DBManager::Import::Retina

  require 'msf/core/db_manager/import/spiceworks'
  include Msf::DBManager::Import::Spiceworks

  require 'msf/core/db_manager/import/wapiti'
  include Msf::DBManager::Import::Wapiti

  # A way to sneak the yield back into the db importer.
  # Used by the SAX parsers.
  def emit(sym,data,&block)
    yield(sym,data)
  end

  def nmap_msf_service_map(proto)
    service_name_map(proto)
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

  # Handles timestamps from Metasploit Express/Pro imports.
  def msf_import_timestamps(opts,obj)
    obj.created_at = opts["created_at"] if opts["created_at"]
    obj.created_at = opts[:created_at] if opts[:created_at]
    obj.updated_at = opts["updated_at"] ? opts["updated_at"] : obj.created_at
    obj.updated_at = opts[:updated_at] ? opts[:updated_at] : obj.created_at
    return obj
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
        return REXML::Document.new(data.gsub(/([\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xff])/){ |x| "\\x%.2x" % x.unpack("C*")[0] })
      end
    end
  end

  ##
  #
  # Import methods
  #
  ##

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
      data = f.read(4)
    end
    if data.nil?
      raise DBImportError.new("Zero-length file")
    end

    case data[0,4]
      when "PK\x03\x04"
        data = Zip::ZipFile.open(filename)
      when "\xd4\xc3\xb2\xa1", "\xa1\xb2\xc3\xd4"
        data = PacketFu::PcapFile.new(:filename => filename)
      else
        ::File.open(filename, 'rb') do |f|
          sz = f.stat.size
          data = f.read(sz)
        end
    end
    if block
      import(args.merge(:data => data)) { |type,data| yield type,data }
    else
      import(args.merge(:data => data))
    end

  end

  # A dispatcher method that figures out the data's file type,
  # and sends it off to the appropriate importer. Note that
  # import_file_detect will raise an error if the filetype
  # is unknown.
  def import(args={}, &block)
    data = args[:data] || args['data']
    wspace = args[:wspace] || args['wspace'] || workspace
    ftype = import_filetype_detect(data)
    yield(:filetype, @import_filedata[:type]) if block
    self.send "import_#{ftype}".to_sym, args, &block
  end

  # Returns one of: :nexpose_simplexml :nexpose_rawxml :nmap_xml :openvas_xml
  # :nessus_xml :nessus_xml_v2 :qualys_scan_xml, :qualys_asset_xml, :msf_xml :nessus_nbe :amap_mlog
  # :amap_log :ip_list, :msf_zip, :libpcap, :foundstone_xml, :acunetix_xml, :appscan_xml
  # :burp_session, :ip360_xml_v3, :ip360_aspl_xml, :nikto_xml
  # If there is no match, an error is raised instead.
  def import_filetype_detect(data)

    if data and data.kind_of? Zip::ZipFile
      raise DBImportError.new("The zip file provided is empty.") if data.entries.empty?
      @import_filedata ||= {}
      @import_filedata[:zip_filename] = File.split(data.to_s).last
      @import_filedata[:zip_basename] = @import_filedata[:zip_filename].gsub(/\.zip$/,"")
      @import_filedata[:zip_entry_names] = data.entries.map {|x| x.name}
      begin
        @import_filedata[:zip_xml] = @import_filedata[:zip_entry_names].grep(/^(.*)_[0-9]+\.xml$/).first || raise
        @import_filedata[:zip_wspace] = @import_filedata[:zip_xml].to_s.match(/^(.*)_[0-9]+\.xml$/)[1]
        @import_filedata[:type] = "Metasploit ZIP Report"
        return :msf_zip
      rescue ::Interrupt
        raise $!
      rescue ::Exception
        raise DBImportError.new("The zip file provided is not a Metasploit ZIP report")
      end
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
            if  line =~ /creator.*\x43\x4f\x52\x45\x20\x49\x4d\x50\x41\x43\x54/i
              @import_filedata[:type] = "CI"
              return :ci_xml
            end
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
      @import_filedata[:type] = "msf_pwdump"
      return :msf_pwdump
    end

    raise DBImportError.new("Could not automatically determine file type")
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
end