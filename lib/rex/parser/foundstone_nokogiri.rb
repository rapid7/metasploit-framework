# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
  module Parser

    # If Nokogiri is available, define Template document class.
    load_nokogiri && class FoundstoneDocument < Nokogiri::XML::SAX::Document

    include NokogiriDocMixin

    def start_document
      @report_type_ok = true # Optimistic
    end

    # Triggered every time a new element is encountered. We keep state
    # ourselves with the @state variable, turning things on when we
    # get here (and turning things off when we exit in end_element()).
    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block
      return unless @report_type_ok
      @state[:current_tag][name] = true
      case name
      when "ReportInfo"
        check_for_correct_report_type(attrs,&block)
      when "Host"
        record_host(attrs)
      when "Service"
        record_service(attrs)
      when "Port", "Protocol", "Banner"
        @state[:has_text] = true
      when "Vuln" # under VulnsFound, ignore risk 0 things
        record_vuln(attrs)
      when "Risk" # for Vuln
        @state[:has_text] = true
      when "CVE" # Under Vuln
        @state[:has_text] = true
      end
    end

    # When we exit a tag, this is triggered.
    def end_element(name=nil)
      block = @block
      return unless @report_type_ok
      case name
      when "Host" # Wrap it up
        collect_host_data
        host_object = report_host &block
        if host_object
          db.report_import_note(@args[:wspace],host_object)
          report_fingerprint(host_object)
          report_services(host_object)
          report_vulns(host_object)
        end
        # Reset the state once we close a host
        @state.delete_if {|k| k != :current_tag}
        @report_data = {:wspace => args[:wspace]}
      when "Port"
        @state[:has_text] = false
        collect_port
      when "Protocol"
        @state[:has_text] = false
        collect_protocol
      when "Banner"
        collect_banner
        @state[:has_text] = false
      when "Service"
        collect_service
      when "Vuln"
        collect_vuln
      when "Risk"
        @state[:has_text] = false
        collect_risk
      when "CVE"
        @state[:has_text] = false
        collect_cve
      end
      @state[:current_tag].delete name
    end

    # Nothing technically stopping us from parsing this as well,
    # but saving this for later
    def check_for_correct_report_type(attrs,&block)
      report_type = attr_hash(attrs)["ReportType"]
      if report_type == "Network Inventory"
        @report_type_ok = true
      else
        if report_type == "Risk Data"
          msg = "The Foundstone/Mcafee report type '#{report_type}' is not currently supported"
          msg << ",\nso no data will be imported. Please use the 'Network Inventory' report instead."
        else
          msg = ".\nThe Foundstone/Macafee report type '#{report_type}' is unsupported."
        end
        db.emit(:warning,msg,&block) if block
        @report_type_ok = false
      end
    end

    def collect_risk
      return unless in_tag("VulnsFound")
      return unless in_tag("HostData")
      return unless in_tag("Host")
      risk = @text.to_s.to_i
      @state[:vuln][:risk] = risk
      @text = nil
    end

    def collect_cve
      return unless in_tag("VulnsFound")
      return unless in_tag("HostData")
      return unless in_tag("Host")
      cve = @text.to_s
      @state[:vuln][:cves] ||= []
      @state[:vuln][:cves] << cve unless cve == "CVE-MAP-NOMATCH"
      @text = nil
    end

    # Determines if we should keep the vuln or not. Note that
    # we cannot tie them to a service.
    def collect_vuln
      return unless in_tag("VulnsFound")
      return unless in_tag("HostData")
      return unless in_tag("Host")
      return if @state[:vuln][:risk] == 0
      @report_data[:vulns] ||= []
      vuln_hash = {}
      vuln_hash[:name] = @state[:vuln]["VulnName"]
      refs = []
      refs << "FID-#{@state[:vuln]["id"]}"
      if @state[:vuln][:cves]
        @state[:vuln][:cves].each {|cve| refs << cve}
      end
      vuln_hash[:refs] = refs
      @report_data[:vulns] << vuln_hash
    end

    # These are per host.
    def record_vuln(attrs)
      return unless in_tag("VulnsFound")
      return unless in_tag("HostData")
      return unless in_tag("Host")
      @state[:vulns] ||= []

      @state[:vuln] = attr_hash(attrs) # id and VulnName
    end

    def record_service(attrs)
      return unless in_tag("ServicesFound")
      return unless in_tag("Host")
      @state[:service] = attr_hash(attrs)
    end

    def collect_port
      return unless in_tag("Service")
      return unless in_tag("ServicesFound")
      return unless in_tag("Host")
      return if @text.nil? || @text.empty?
      @state[:service][:port] = @text.strip
      @text = nil
    end

    def collect_protocol
      return unless in_tag("Service")
      return unless in_tag("ServicesFound")
      return unless in_tag("Host")
      return if @text.nil? || @text.empty?
      @state[:service][:proto] = @text.strip
      @text = nil
    end

    def collect_banner
      return unless in_tag("Service")
      return unless in_tag("ServicesFound")
      return unless in_tag("Host")
      return if @text.nil? || @text.empty?
      banner = normalize_foundstone_banner(@state[:service]["ServiceName"],@text)
      unless banner.nil? || banner.empty?
        @state[:service][:banner] = banner
      end
      @text = nil
    end

    def collect_service
      return unless in_tag("ServicesFound")
      return unless in_tag("Host")
      return unless @state[:service][:port]
      @report_data[:ports] ||= []
      port_hash = {}
       port_hash[:port] = @state[:service][:port]
       port_hash[:proto] = @state[:service][:proto]
       port_hash[:info] = @state[:service][:banner]
       port_hash[:name] = db.nmap_msf_service_map(@state[:service]["ServiceName"])
      @report_data[:ports] << port_hash
    end

    def record_host(attrs)
      return unless in_tag("HostData")
      @state[:host] = attr_hash(attrs)
    end

    def collect_host_data
      @report_data[:host] = @state[:host]["IPAddress"]
      if @state[:host]["NBName"] && !@state[:host]["NBName"].empty?
        @report_data[:name] = @state[:host]["NBName"]
      elsif @state[:host]["DNSName"] && !@state[:host]["DNSName"].empty?
        @report_data[:name] = @state[:host]["DNSName"]
      end
      if @state[:host]["OSName"] && !@state[:host]["OSName"].empty?
        @report_data[:os_fingerprint] = @state[:host]["OSName"]
      end
      @report_data[:state] = Msf::HostState::Alive
      @report_data[:mac] = @state[:mac] if @state[:mac]
    end

    def report_host(&block)
      return unless in_tag("HostData")
      if host_is_okay
        db.emit(:address,@report_data[:host],&block) if block
        host_info = @report_data.merge(:workspace => @args[:wspace])
        db_report(:host,host_info)
      end
    end

    def report_fingerprint(host_object)
      fp_note = {
        :workspace => host_object.workspace,
        :host => host_object,
        :type => 'host.os.foundstone_fingerprint',
        :data => {:os => @report_data[:os_fingerprint] }
      }
      db_report(:note, fp_note)
    end

    def report_services(host_object)
      return unless in_tag("HostData")
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:ports]
      return if @report_data[:ports].empty?
      @report_data[:ports].each do |svc|
        db_report(:service, svc.merge(:host => host_object))
      end
    end

    def report_vulns(host_object)
      return unless in_tag("HostData")
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:vulns]
      return if @report_data[:vulns].empty?
      @report_data[:vulns].each do |vuln|
        db_report(:vuln, vuln.merge(:host => host_object))
      end
    end

    # Foundstone's banners are pretty free-form
    # and often not just banners. Clean them up
    # for the :info field, delegate off for other
    # protocol data we can use.
    def normalize_foundstone_banner(service,banner)
      return "" if(banner.nil? || banner.strip.empty?)
      if first_line_only? service
        return (first_line banner)
      elsif needs_more_processing? service
        return process_service(service,banner)
      else
        return (first_line banner)
      end
    end

    # Services where we only care about the first
    # line of the banner tag.
    def first_line_only?(service)
      svcs = %w{
        vnc ftp ftps smtp oracle-tns nntp ssh ntp
      }
      9.times {|i| svcs << "vnc-#{i}"}
      svcs.include? service
    end

    # Services where we need to do more processing
    # before handing the banner back.
    def needs_more_processing?(service)
      svcs = %w{
        microsoft-ds loc-srv http https sunrpc netbios-ns
      }
      svcs.include? service
    end

    def first_line(str)
      str.split("\n").first.to_s.strip
    end

    # XXX: Actually implement more of these
    def process_service(service,banner)
      meth = "process_service_#{service.gsub("-","_")}"
      if self.respond_to? meth
        self.send meth, banner
      else
        return (first_line banner)
      end
    end

    # XXX: Register a proper netbios note as the regular
    # scanner does.
    def process_service_netbios_ns(banner)
      mac_regex = /[0-9A-Fa-f:]{17}/
      @state[:mac] = banner[mac_regex]
      first_line banner
    end

    # XXX: Make this behave more like the smb scanner
    def process_service_microsoft_ds(banner)
      lm_regex = /Native LAN Manager/
      lm_banner = nil
      banner.each_line { |line|
        if line[lm_regex]
          lm_banner = line
          break
        end
      }
      lm_banner || first_line(banner)
    end

    def process_service_http(banner)
      server = nil
      banner.each_line do |line|
        if line =~ /^Server:\s+(.*)/
          server = $1
          break
        end
      end
      server || first_line(banner)
    end

    alias :process_service_https :process_service_http
    alias :process_service_rtsp :process_service_http

  end

end
end

