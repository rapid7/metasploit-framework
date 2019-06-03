#
# Standard library
#

require 'fileutils'
require 'tmpdir'
require 'uri'

#
# Gems
#

require 'packetfu'

module Msf::DBManager::Import
  autoload :Acunetix, 'msf/core/db_manager/import/acunetix'
  autoload :Amap, 'msf/core/db_manager/import/amap'
  autoload :Appscan, 'msf/core/db_manager/import/appscan'
  autoload :BurpIssue, 'msf/core/db_manager/import/burp_issue'
  autoload :BurpSession, 'msf/core/db_manager/import/burp_session'
  autoload :CI, 'msf/core/db_manager/import/ci'
  autoload :Foundstone, 'msf/core/db_manager/import/foundstone'
  autoload :FusionVM, 'msf/core/db_manager/import/fusion_vm'
  autoload :GPP, 'msf/core/db_manager/import/gpp'
  autoload :IP360, 'msf/core/db_manager/import/ip360'
  autoload :IPList, 'msf/core/db_manager/import/ip_list'
  autoload :Libpcap, 'msf/core/db_manager/import/libpcap'
  autoload :MBSA, 'msf/core/db_manager/import/mbsa'
  autoload :MetasploitFramework, 'msf/core/db_manager/import/metasploit_framework'
  autoload :Nessus, 'msf/core/db_manager/import/nessus'
  autoload :Netsparker, 'msf/core/db_manager/import/netsparker'
  autoload :Nexpose, 'msf/core/db_manager/import/nexpose'
  autoload :Nikto, 'msf/core/db_manager/import/nikto'
  autoload :Nmap, 'msf/core/db_manager/import/nmap'
  autoload :OpenVAS, 'msf/core/db_manager/import/open_vas'
  autoload :Outpost24, 'msf/core/db_manager/import/outpost24'
  autoload :Qualys, 'msf/core/db_manager/import/qualys'
  autoload :Report, 'msf/core/db_manager/import/report'
  autoload :Retina, 'msf/core/db_manager/import/retina'
  autoload :Spiceworks, 'msf/core/db_manager/import/spiceworks'
  autoload :Wapiti, 'msf/core/db_manager/import/wapiti'

  include Msf::DBManager::Import::Acunetix
  include Msf::DBManager::Import::Amap
  include Msf::DBManager::Import::Appscan
  include Msf::DBManager::Import::BurpIssue
  include Msf::DBManager::Import::BurpSession
  include Msf::DBManager::Import::CI
  include Msf::DBManager::Import::Foundstone
  include Msf::DBManager::Import::FusionVM
  include Msf::DBManager::Import::GPP
  include Msf::DBManager::Import::IP360
  include Msf::DBManager::Import::IPList
  include Msf::DBManager::Import::Libpcap
  include Msf::DBManager::Import::MBSA
  include Msf::DBManager::Import::MetasploitFramework
  include Msf::DBManager::Import::Nessus
  include Msf::DBManager::Import::Netsparker
  include Msf::DBManager::Import::Nexpose
  include Msf::DBManager::Import::Nikto
  include Msf::DBManager::Import::Nmap
  include Msf::DBManager::Import::OpenVAS
  include Msf::DBManager::Import::Outpost24
  include Msf::DBManager::Import::Qualys
  include Msf::DBManager::Import::Report
  include Msf::DBManager::Import::Retina
  include Msf::DBManager::Import::Spiceworks
  include Msf::DBManager::Import::Wapiti

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
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework)
    preserve_hosts = args[:task].options["DS_PRESERVE_HOSTS"] if args[:task].present? && args[:task].options.present?
    wspace.update_attribute(:import_fingerprint, true)
    existing_host_ids = wspace.hosts.map(&:id)
    data = args[:data] || args['data']
    ftype = import_filetype_detect(data)
    yield(:filetype, @import_filedata[:type]) if block
    self.send "import_#{ftype}".to_sym, args.merge(workspace: wspace.name), &block
    # post process the import here for missing default port maps
    mrefs, mports, _mservs = Msf::Modules::Metadata::Cache.instance.all_remote_exploit_maps
    # the map build above is a little expensive, another option is to do
    # a host by ref search for each vuln ref and then check port reported for each module
    # IMHO this front loaded cost here is worth it with only a small number of modules
    # compared to the vast number of possible references offered by a Vulnerability scanner.
    deferred_service_ports = [ 139 ] # I hate special cases, however 139 is no longer a preferred default

    new_host_ids = Mdm::Host.where(workspace: wspace).map(&:id)
    (new_host_ids - existing_host_ids).each do |id|
      imported_host = Mdm::Host.where(id: id).first
      next if imported_host.vulns.nil? || imported_host.vulns.empty?
      # get all vulns with ports
      with_ports = []
      imported_host.vulns.each do |vuln|
        next if vuln.service.nil?
        with_ports << vuln.name
      end

      imported_host.vulns.each do |vuln|
        # now get default ports for vulns where service is nil
        next unless vuln.service.nil?
        next if with_ports.include?(vuln.name)
        serv = nil

        # Module names that match this vulnerability
        matched = mrefs.values_at(*(vuln.refs.map { |x| x.name.upcase } & mrefs.keys)).map { |x| x.values }.flatten.uniq
        next if matched.empty?
        match_names = matched.map { |mod| mod.fullname }

        second_pass_services = []

        imported_host.services.each do |service|
          if deferred_service_ports.include?(service.port)
            second_pass_services << service
            next
          end
          next unless mports[service.port]
          if (match_names - mports[service.port].keys).count < match_names.count
            serv = service
            break
          end
        end

        # post process any deferred services if no match has been found
        if serv.nil? && !second_pass_services.empty?
          second_pass_services.each do |service|
            next unless mports[service.port]
            if (match_names - mports[service.port].keys).count < match_names.count
              serv = service
              break
            end
          end
        end

        next if serv.nil?
        vuln.service = serv
        vuln.save

      end
    end
    if preserve_hosts
      (new_host_ids - existing_host_ids).each do |id|
        Mdm::Host.where(id: id).first.normalize_os
      end
    else
      Mdm::Host.where(workspace: wspace).each(&:normalize_os)
    end
    wspace.update_attribute(:import_fingerprint, false)
  end

  #
  # Generic importer that automatically determines the file type being
  # imported.  Since this looks for vendor-specific strings in the given
  # file, there shouldn't be any false detections, but no guarantees.
  #
  def import_file(args={}, &block)
    filename = args[:filename] || args['filename']
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework)
    @import_filedata            = {}
    @import_filedata[:filename] = filename

    data = ""
    ::File.open(filename, 'rb') do |f|
      # This check is the largest (byte-wise) that we need to do
      # since the other 4-byte checks will be subsets of this larger one.
      data = f.read(Metasploit::Credential::Exporter::Pwdump::FILE_ID_STRING.size)
    end
    if data.nil?
      raise Msf::DBImportError.new("Zero-length file")
    end

    if data.index(Metasploit::Credential::Exporter::Pwdump::FILE_ID_STRING)
      data = ::File.open(filename, 'rb')
    else
      case data[0,4]
      when "PK\x03\x04"
        # When Msf::DBManager::Import::MetasploitFramework is included, it's child namespace of
        # Msf::DBManager::Import::MetasploitFramework::Zip becomes resolvable as Zip here, so need to use ::Zip so Zip
        # is resolved as one from rubyzip gem.
        data = ::Zip::File.open(filename)
      when "\xd4\xc3\xb2\xa1".force_encoding('ASCII-8BIT'), "\xa1\xb2\xc3\xd4".force_encoding('ASCII-8BIT')
        data = PacketFu::PcapFile.new(:filename => filename)
      else
        ::File.open(filename, 'rb') do |f|
          sz = f.stat.size
          data = f.read(sz)
        end
      end
    end

    # Override REXML's expansion text limit to 50k (default: 10240 bytes)
    REXML::Security.entity_expansion_text_limit = 51200

    if block
      import(args.merge(data: data, workspace: wspace.name)) { |type,data| yield type,data }
    else
      import(args.merge(data: data, workspace: wspace.name))
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
  # :gpp_xml
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
  # @raise [Msf::DBImportError] if the type can't be detected
  def import_filetype_detect(data)
    # When Msf::DBManager::Import::MetasploitFramework is included, it's child namespace of
    # Msf::DBManager::Import::MetasploitFramework::Zip becomes resolvable as Zip here, so need to use ::Zip so Zip
    # is resolved as one from rubyzip gem.
    if data and data.kind_of? ::Zip::File
      if data.entries.empty?
        raise Msf::DBImportError.new("The zip file provided is empty.")
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
        raise Msf::DBImportError.new("The zip file provided is not a Metasploit Zip Export")
      end

      @import_filedata[:zip_xml] = xml_files.first
      @import_filedata[:type] = "Metasploit Zip Export"

      return :msf_zip
    end

    if data and data.kind_of? PacketFu::PcapFile
      # Don't check for emptiness here because unlike other formats, we
      # haven't read any actual data in yet, only magic bytes to discover
      # that this is indeed a pcap file.
      #raise Msf::DBImportError.new("The pcap file provided is empty.") if data.body.empty?
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
    data.force_encoding(Encoding::ASCII_8BIT)
    if data and data.to_s.strip.length == 0
      raise Msf::DBImportError.new("The data provided to the import function was empty")
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
    elsif (firstline.index(/<get_results_response status=['"]200['"] status_text=['"]OK['"]>/))
      @import_filedata[:type] = "OpenVAS XML"
      return :openvas_new_xml
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
    elsif (data[0,1024] =~ /<!ATTLIST\s+issues\s+burpVersion/)
      @import_filedata[:type] = "Burp Issue XML"
      return :burp_issue_xml
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
          if line.start_with?('<nmaprun scanner="masscan"')
            @import_filedata[:type] = "Masscan XML"
          else
            @import_filedata[:type] = "Nmap XML"
          end
          return :nmap_xml
        when "openvas-report"
          @import_filedata[:type] = "OpenVAS"
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
        when /MetasploitV5/
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
        when /Groups|DataSources|Drives|ScheduledTasks|NTServices/
          @import_filedata[:type] = "Group Policy Preferences Credentials"
          return :gpp_xml
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

    raise Msf::DBImportError.new("Could not automatically determine file type")
  end

  # Handles timestamps from Metasploit Express/Pro imports.
  def msf_import_timestamps(opts,obj)
    obj.created_at = opts["created_at"] if opts["created_at"]
    obj.created_at = opts[:created_at] if opts[:created_at]
    obj.updated_at = opts["updated_at"] ? opts["updated_at"] : obj.created_at
    obj.updated_at = opts[:updated_at] ? opts[:updated_at] : obj.created_at
    return obj
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

  # Boils down the validate_import_file to a boolean
  def validate_import_file(data)
    begin
      import_filetype_detect(data)
    rescue Msf::DBImportError
      return false
    end
    return true
  end
end
