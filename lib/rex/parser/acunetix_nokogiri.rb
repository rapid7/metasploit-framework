# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"
require 'rex'
require 'uri'

module Rex
  module Parser

    # If Nokogiri is available, define the Acunetix document class.
    load_nokogiri && class AcunetixDocument < Nokogiri::XML::SAX::Document

    include NokogiriDocMixin

    # The resolver prefers your local /etc/hosts (or windows equiv), but will
    # fall back to regular DNS. It retains a cache for the import to avoid
    # spamming your network with DNS requests.
    attr_reader :resolv_cache

    # If name resolution of the host fails out completely, you will not be
    # able to import that Scan task. Other scan tasks in the same report
    # should be unaffected.
    attr_reader :parse_warnings

    def start_document
      @parse_warnings = []
      @resolv_cache = {}
      @host_object = nil
    end

    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block
      @state[:current_tag][name] = true
      case name
      when "Scan" # Start of the thing.
        @state[:report_item] = {}
      when "Name", "StartURL", "StartTime", "Banner", "Os", "Text", "Severity", "CWE", "URL", "Parameter"
        @state[:has_text] = true
      when "LoginSequence" # Skipping for now
      when "ReportItem"
        @state[:report_item] = {}
      when "Crawler"
        record_crawler(attrs)
      when "FullURL"
        @state[:has_text] = true
      when "Variable"
        record_variable(attrs)
      when "Request", "Response"
        @state[:has_text] = true
      end
    end

    def end_element(name=nil)
      block = @block
      case name
      when "Scan"
        # Clears most of the @state out, we're done with this web site.
        @state.delete_if {|k| k != :current_tag}
      when "Name"
        @state[:has_text] = false
        collect_scan_name
        collect_report_item_name
        @text = nil
      when "StartURL" # Populates @state[:starturl_uri], we use this a lot
        @state[:has_text] = false
        # StartURL does not always include the scheme
        @text.prepend("http://") unless URI.parse(@text).scheme
        collect_host
        collect_service_from_url
        @text = nil
        handle_parse_warnings &block
        @host_object = report_host &block
        if @host_object
          report_starturl_service(&block)
          db.report_import_note(@args[:workspace],@host_object)
        end
      when "StartTime"
        @state[:has_text] = false
        @state[:timestamp] = @text.to_s.tr!(',','').tr!('/','-')
        @text = nil
      when "Text"
        @state[:has_text] = false
        service = collect_service_from_kbitem_text
        @text = nil
        return unless service
        handle_parse_warnings &block
        if @host_object
          report_kbitem_service(service,&block)
        end
      when "Severity"
        @state[:has_text] = false
        collect_report_item_severity
        @text = nil
      when "CWE"
        @state[:has_text] = false
        collect_report_item_cwe
        @text = nil
      when "URL"
        @state[:has_text] = false
        collect_report_item_reference_url
        @text = nil
      when "Parameter"
        @state[:has_text] = false
        collect_report_item_parameter
        @text = nil
      when "ReportItem"
        vuln = collect_vuln_from_report_item
        if vuln.nil?
          @state[:page_request] = @state[:page_response] = nil
          return
        end
        handle_parse_warnings &block 
        if @state[:vuln_info][:refs].nil?
          report_web_vuln(&block)
        else
          report_other_vuln(&block)
        end
        @state[:page_request] = @state[:page_response] = nil
      when "Banner"
        @state[:has_text] = false
        collect_and_report_banner
      when "Os"
        @state[:has_text] = false
        report_os_fingerprint
      when "LoginSequence" # This comes up later in the report anyway
      when "Crawler"
        report_starturl_web_site(&block)
      when "FullURL"
        @state[:has_text] = false
        report_web_site(@text,&block)
        @text = nil
      when "Inputs"
        report_web_form(&block)
      when "Request"
        @state[:has_text] = false
        collect_page_request
        @text = nil
      when "Response"
        @state[:has_text] = false
        collect_page_response
        @text = nil
        report_web_page(&block)
      end
      @state[:current_tag].delete name
    end

    def collect_page_response
      return unless in_tag("TechnicalDetails")
      return unless in_tag("ReportItem")
      return unless @text
      return if @text.to_s.empty?
      @state[:page_response] = @text
    end

    def collect_page_request
      return unless in_tag("TechnicalDetails")
      return unless in_tag("ReportItem")
      return unless @text
      return if @text.to_s.empty?
      @state[:page_request] = @text
    end

    def collect_scan_name
      return unless in_tag("Scan")
      return if in_tag("ReportItems")
      return if in_tag("Crawler")
      return unless @text
      return if @text.strip.empty?
      @state[:scan_name] = @text.strip
    end

    def collect_host
      return unless in_tag("Scan")
      return unless @text
      return if @text.strip.empty?
      uri = URI.parse(@text) rescue nil
      return unless uri
      address = resolve_scan_starturl_address(uri)
      @report_data[:host] = address
      @report_data[:state] = Msf::HostState::Alive
    end

    def collect_service_from_url
      return unless @report_data[:host]
      return unless in_tag("Scan")
      return unless @text
      return if @text.strip.empty?
      uri = URI.parse(@text) rescue nil
      return unless uri
      @state[:starturl_uri] = uri
      @report_data[:ports] ||= []
      @report_data[:ports] << @state[:starturl_port]
    end

    def collect_service_from_kbitem_text
      return unless @host_object
      return unless in_tag("Scan")
      return unless in_tag("KBase")
      return unless in_tag("KBItem")
      return unless @text
      return if @text.strip.empty?
      return unless @text =~ /server is running/
      matched = / (?<name>\w+) server is running on (?<proto>\w+) port (?<portnum>\d+)\./.match(@text)
      @report_data[:ports] ||= []
      @report_data[:ports] << matched[:portnum]
      return matched
    end

    def collect_vuln_from_report_item
      @state[:vuln_info] = nil
      return unless @host_object
      return unless in_tag("Scan")
      return unless in_tag("ReportItems")
      return unless in_tag("ReportItem")
      return unless @state[:report_item][:name]
      return unless @state[:report_item][:severity]
      return unless @state[:report_item][:severity].downcase == "high"

      @state[:vuln_info] = {}
      @state[:vuln_info][:name] = @state[:report_item][:name]
      if @state[:page_request_verb].nil? && @state[:report_item][:name] =~ /deprecated/
        # Treating this as a regular vuln, not web-specific
        @state[:vuln_info][:refs] = ["ACX-#{@state[:report_item][:reference_url]}"]
        unless @state[:report_item_cwe].nil?
          @state[:vuln_info][:refs][0] << ",#{@state[:report_item][:cwe]}"
        end
      end
      @state[:vuln_info][:severity] = @state[:report_item][:severity].downcase
      @state[:vuln_info][:cwe] = @state[:report_item][:cwe]
      return @state[:vuln_info]
    end

    def collect_and_report_banner
      return unless (svc = @state[:starturl_service_object]) # Yes i want assignment
      return unless @text
      return if @text.strip.empty?
      return unless in_tag("Scan")
      svc_info = {
        :host => svc.host,
        :port => svc.port,
        :proto => svc.proto,
        :info => @text.strip
      }
      db_report(:service, svc_info)
      @text = nil
    end

    def collect_report_item_name
      return unless in_tag("ReportItem")
      return unless @text
      return if @text.strip.empty?
      @state[:report_item][:name] = @text
    end

    def collect_report_item_severity
      return unless in_tag("ReportItem")
      return unless @text
      return if @text.strip.empty?
      @state[:report_item][:severity] = @text
    end

    def collect_report_item_cwe
      return unless in_tag("ReportItem")
      return unless @text
      return if @text.strip.empty?
      @state[:report_item][:cwe] = @text
    end

    def collect_report_item_reference_url
      return unless in_tag("ReportItem")
      return unless in_tag("References")
      return unless in_tag("Reference")
      return unless @text
      return if @text.strip.empty?
      @state[:report_item][:reference_url] = @text
    end

    def collect_report_item_parameter
      return unless in_tag("ReportItem")
      return unless @text
      return if @text.strip.empty?
      @state[:report_item][:parameter] = @text
    end

    # @state[:fullurl] is set by report_web_site
    def record_variable(attrs)
      return unless in_tag("Inputs")
      return unless @state[:fullurl].kind_of? URI
      method = attr_hash(attrs)["Type"]
      return unless method
      return if method.strip.empty?
      @state[:form_variables] ||= []
      @state[:form_variables] << [attr_hash(attrs)["Name"],method]
    end

    def record_crawler(attrs)
      return unless in_tag("Scan")
      return unless @state[:starturl_service_object]
      starturl = attr_hash(attrs)["StartUrl"]
      return unless starturl
      @state[:crawler_starturl] = starturl
    end

    def report_web_form(&block)
      return unless in_tag("SiteFiles")
      return unless @state[:web_site]
      return unless @state[:fullurl].kind_of? URI
      return unless @state[:form_variables].kind_of? Array
      return if @state[:form_variables].empty?
      method = parse_method(@state[:form_variables].first[1])
      vars = @state[:form_variables].map {|x| x[0]}
      form_info = {}
      form_info[:web_site] = @state[:web_site]
      form_info[:path] = @state[:fullurl].path
      form_info[:query] = @state[:fullurl].query
      form_info[:method] = method
      form_info[:params] = vars
      url = @state[:fullurl].to_s
      db.emit(:web_form,url,&block) if block
      db_report(:web_form,form_info)
      @state[:fullurl] = nil
      @state[:form_variables] = nil
    end

    def report_web_page(&block)
      return if should_skip_this_page
      return unless @state[:web_site]
      @state[:page_request_verb] = nil
      return unless @state[:page_request]
      return if @state[:page_request].strip.empty?
      verb,path,query_string = parse_request(@state[:page_request])
      return unless path
      @state[:page_request_verb] = verb
      web_page_info = {}
      if @state[:page_response].strip.blank?
        web_page_info[:code] = ""
        web_page_info[:headers] = {}
        web_page_info[:body] = ""
      else
        parsed_response = parse_response(@state[:page_response])
        return unless parsed_response
        web_page_info[:code] = parsed_response[:code].to_i
        web_page_info[:headers] = parsed_response[:headers]
        web_page_info[:body] = parsed_response[:body]
      end
      web_page_info[:web_site] = @state[:web_site]
      web_page_info[:path] = path
      web_page_info[:query] = query_string || ""
      url = ""
      url << @state[:web_site].service.name.to_s << "://"
      url << @state[:web_site].vhost.to_s << ":"
      url << path
      uri = URI.parse(url) rescue nil
      return unless uri # Sanity checker
      db.emit(:web_page, url, &block) if block
      web_page_object = db_report(:web_page,web_page_info)
      @state[:web_page] = web_page_object
    end

    def report_web_vuln(&block)
      return if should_skip_this_page
      return unless @state[:web_page]
      return unless @state[:web_site]
      return unless @state[:vuln_info]
      
      web_vuln_info = {}
      web_vuln_info[:web_site] = @state[:web_site]
      web_vuln_info[:path] = @state[:web_page][:path]
      web_vuln_info[:query] = @state[:web_page][:query]
      web_vuln_info[:method] = @state[:page_request_verb]
      web_vuln_info[:pname] = ""
      if @state[:page_response].blank?
        web_vuln_info[:proof] = "<empty response>"
      else
        web_vuln_info[:proof] = @state[:page_response]
      end
      web_vuln_info[:risk] = 5
      web_vuln_info[:params] = []
      unless @state[:report_item][:parameter].blank?
        # Acunetix only lists a single paramter...
        web_vuln_info[:params] << [ @state[:report_item][:parameter].to_s, "" ]
      end
      web_vuln_info[:category] = "imported"
      web_vuln_info[:confidence] = 100
      web_vuln_info[:name] = @state[:vuln_info][:name]

      db.emit(:web_vuln, web_vuln_info[:name], &block) if block
      vuln = db_report(:web_vuln, web_vuln_info)
    end

    def report_other_vuln(&block)
      return if should_skip_this_page
      return unless @state[:vuln_info]

      db.emit(:vuln, @state[:vuln_info][:name], &block) if block
      db_report(:vuln, @state[:vuln_info].merge(:host => @host_object))
    end

    # Reasons why we shouldn't collect a particular web page.
    def should_skip_this_page
      if @state[:report_item][:name] =~ /Unrestricted File Upload/
        # This means that the page being collected is something the
        # auditor put there, so it's not useful to report on.
        return true
      end
      return false
    end

    # XXX Rex::Proto::Http::Packet seems broken for
    # actually parsing requests and responses, but all I
    # need are the headers anyway
    def parse_request(request)
      headers = Rex::Proto::Http::Packet::Header.new
      headers.from_s request.dup # It's destructive.
      return unless headers.cmd_string
      verb,req = headers.cmd_string.split(/\s+/)
      return unless verb
      return unless req
      path,query_string = req.split(/\?/)[0,2]
      return verb,path,query_string
    end

    def parse_response(response)
      headers = Rex::Proto::Http::Packet::Header.new
      headers.from_s response.dup # It's destructive.
      return unless headers.cmd_string
      http,code,msg = headers.cmd_string.split(/\s+/)
      return unless code
      return unless code.to_i.to_s == code
      parsed = {}
      parsed[:code] = code
      parsed[:headers] = {}
      headers.each do |k,v|
        parsed[:headers][k.to_s.downcase] = []
        parsed[:headers][k.to_s.downcase] << v
      end
      parsed[:body] = "" # We never seem to get this from Acunetix
      parsed
    end

    # Don't cause the web report to die just because we can't tell
    # what method was used -- default to GET. Sometimes it's just "POST," and
    # sometimes it's "URL encoded POST," and sometimes it might be something
    # else.
    def parse_method(meth)
      verbs = "(GET|POST|PATH)"
      real_method = meth.match(/^\s*#{verbs}/)
      real_method ||= meth.match(/\s*#{verbs}\s*$/)
      ( real_method && real_method[1] ) ? real_method[1] : "GET"
    end

    def report_host(&block)
      return unless @report_data[:host]
      return unless in_tag("Scan")
      if host_is_okay
        db.emit(:address,@report_data[:host],&block) if block
        host_info = @report_data.merge(:workspace => @args[:workspace])
        db_report(:host,host_info)
      end
    end

    # The service is super important, so we hang on to it for the
    # rest of the scan.
    def report_starturl_service(&block)
      return unless @host_object
      return unless @state[:starturl_uri]
      name = @state[:starturl_uri].scheme
      port = @state[:starturl_uri].port
      addr = @host_object.address
      svc = {
        :host => @host_object,
        :port => port,
        :name => name.dup,
        :proto => "tcp"
      }
      if name and port
        db.emit(:service,[addr,port].join(":"),&block) if block
        @state[:starturl_service_object] = db_report(:service,svc)
      end
    end

    def report_kbitem_service(service,&block)
      return unless @host_object
      return unless @state[:starturl_uri]
      addr = @host_object.address
      svc = {
        :host => @host_object,
        :port => service[:portnum].to_i,
        :name => service[:name].dup.downcase,
        :proto => service[:proto].dup.downcase
      }
      if service[:name] and service[:portnum]
        db.emit(:service,[addr,service[:portnum]].join(":"),&block) if block
        db_report(:service,svc)
      end
    end

    def report_web_site(url,&block)
      return unless in_tag("Crawler")
      return unless url
      return if url.strip.empty?
      uri = URI.parse(url) rescue nil
      return unless uri
      host = uri.host
      port = uri.port
      scheme = uri.scheme
      return unless scheme[/^https?/]
      return unless (host && port && scheme)
      address = resolve_address(host)
      return unless address
      # If we didn't create the service, we don't care about the site
      service_object = db.get_service @args[:workspace], address, "tcp", port
      return unless service_object
      web_site_info = {
        :workspace => @args[:workspace],
        :service => service_object,
        :vhost => host,
        :ssl => (scheme == "https")
      }
      @state[:web_site] = db_report(:web_site,web_site_info)
      @state[:fullurl] = uri
    end

    def report_starturl_web_site(&block)
      return unless @state[:crawler_starturl]
      starturl = @state[:crawler_starturl].dup
      report_web_site(starturl,&block)
    end

    def report_os_fingerprint
      return unless @state[:starturl_service_object]
      return unless @text
      return if @text.strip.empty?
      return unless in_tag("Scan")
      host = @state[:starturl_service_object].host
      fp_note = {
        :workspace => host.workspace,
        :host => host,
        :type => 'host.os.acunetix_fingerprint',
        :data => {:os => @text}
      }
      db_report(:note, fp_note)
      @text = nil
    end

    def resolve_port(uri)
      @state[:port] = uri.port
      unless @state[:port]
        @parse_warnings << "Could not determine a port for '#{@state[:scan_name]}'"
      end
      @state[:port] = uri.port
    end

    def resolve_address(host)
      return @resolv_cache[host] if @resolv_cache[host]
      address = Rex::Socket.resolv_to_dotted(host) rescue nil
      @resolv_cache[host] = address
      return address
    end

    def resolve_scan_starturl_address(uri)
      if uri.host
        address = resolve_address(uri.host)
        unless address
          @parse_warnings << "Could not resolve address for '#{uri.host}', skipping '#{@state[:scan_name]}'"
        end
      else
        @parse_warnings << "Could not determine a host for '#{@state[:scan_name]}'"
      end
      address
    end

    def handle_parse_warnings(&block)
      return if @parse_warnings.empty?
      @parse_warnings.each do |pwarn|
        db.emit(:warning, pwarn, &block) if block
      end
    end

  end
  end
end

