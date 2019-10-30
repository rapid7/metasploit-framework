# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
  module Parser

    # If Nokogiri is available, define AppScan document class.
    load_nokogiri && class AppscanDocument < Nokogiri::XML::SAX::Document

    include NokogiriDocMixin

    # The resolver prefers your local /etc/hosts (or windows equiv), but will
    # fall back to regular DNS. It retains a cache for the import to avoid
    # spamming your network with DNS requests.
    attr_reader :resolv_cache

    # If name resolution of the host fails out completely, you will not be
    # able to import that Scan task. Other scan tasks in the same report
    # should be unaffected.
    attr_reader :parse_warning

    def start_document
      @parse_warnings = []
      @resolv_cache = {}
    end

    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block
      @state[:current_tag][name] = true
      case name
      when "Issue" # Start of the stuff we want
        collect_issue(attrs)
      when "Entity" # Start of the stuff we want
        collect_entity(attrs)
      when "Severity", "Url", "OriginalHttpTraffic"
        @state[:has_text] = true
      end
    end

    def end_element(name=nil)
      block = @block
      case name
      when "Issue" # Wrap it up
        record_issue
        # Reset the state once we close an issue
        @state = @state.select do
          |k| [:current_tag, :web_sites].include? k
        end
      when "Url" # Populates @state[:web_site]
        @state[:has_text] = false
        record_url
        @text = nil
        report_web_site(&block)
        handle_parse_warnings(&block)
      when "Severity"
        @state[:has_text] = false
        record_risk
        @text = nil
      when "OriginalHttpTraffic" # Request and response
        @state[:has_text] = false
        record_request_and_response
        report_service_info
        page_info = report_web_page(&block)
        if page_info
          form_info = report_web_form(page_info,&block)
          if form_info
            report_web_vuln(form_info,&block)
          end
        end
        @text = nil
      end
      @state[:current_tag].delete name
    end

    def report_web_vuln(form_info,&block)
      return unless(in_issue && has_text)
      return unless form_info.kind_of? Hash
      return unless @state[:issue]
      return unless @state[:issue]["Noise"]
      return unless @state[:issue]["Noise"].to_s.downcase == "false"
      return unless @state[:issue][:vuln_param]
      web_vuln_info = {}
      web_vuln_info[:web_site] = form_info[:web_site]
      web_vuln_info[:path] = form_info[:path]
      web_vuln_info[:query] = form_info[:query]
      web_vuln_info[:method] = form_info[:method]
      web_vuln_info[:params] = form_info[:params]
      web_vuln_info[:pname] = @state[:issue][:vuln_param]
      web_vuln_info[:proof] = "" # TODO: pick this up from <Difference> maybe?
      web_vuln_info[:risk] = @state[:issue][:risk]
      web_vuln_info[:name] = @state[:issue]["IssueTypeID"]
      web_vuln_info[:category] = "imported"
      web_vuln_info[:confidence] = 100 # Seems pretty binary, noise or not
      db.emit(:web_vuln, web_vuln_info[:name], &block) if block
      web_vuln = db_report(:web_vuln, web_vuln_info)
    end

    def collect_entity(attrs)
      return unless in_issue
      return unless @state[:issue].kind_of? Hash
      ent_hash = attr_hash(attrs)
      return unless ent_hash
      return unless ent_hash["Type"].to_s.downcase == "parameter"
      @state[:issue][:vuln_param] = ent_hash["Name"]
    end

    def report_web_form(page_info,&block)
      return unless(in_issue && has_text)
      return unless page_info.kind_of? Hash
      return unless @state[:request_body]
      return if @state[:request_body].strip.empty?
      web_form_info = {}
      web_form_info[:web_site] = page_info[:web_site]
      web_form_info[:path] = page_info[:path]
      web_form_info[:query] = page_info[:query]
      web_form_info[:method] = @state[:request_headers].cmd_string.split(/\s+/)[0]
      parsed_params = parse_params(@state[:request_body])
      return unless parsed_params
      return if parsed_params.empty?
      web_form_info[:params] = parsed_params
      web_form = db_report(:web_form, web_form_info)
      @state[:web_forms] ||= []
      unless @state[:web_forms].include? web_form
        db.emit(:web_form, @state[:uri].to_s, &block) if block
        @state[:web_forms] << web_form
      end
      web_form_info
    end

    def parse_params(request_body)
      return unless request_body
      pairs = request_body.split(/&/)
      params = []
      pairs.each do |pair|
        param,value = pair.split("=",2)
        params << [param,""] # Can't tell what's default
      end
      params
    end

    def report_web_page(&block)
      return unless(in_issue && has_text)
      return unless @state[:web_site].present?
      return unless @state[:response_headers].present?
      return unless @state[:uri].present?
      web_page_info = {}
      web_page_info[:web_site] = @state[:web_site]
      web_page_info[:path] = @state[:uri].path
      web_page_info[:body] = @state[:response_body].to_s
      web_page_info[:query] = @state[:uri].query
      code = @state[:response_headers].cmd_string.split(/\s+/)[1]
      return unless code
      web_page_info[:code] = code
      parsed_headers = {}
      @state[:response_headers].each do |k,v|
        parsed_headers[k.to_s.downcase] ||= []
        parsed_headers[k.to_s.downcase] << v
      end
      return if parsed_headers.empty?
      web_page_info[:headers] = parsed_headers
      web_page = db_report(:web_page, web_page_info)
      @state[:web_pages] ||= []
      unless @state[:web_pages].include? web_page
        db.emit(:web_page, @state[:uri].to_s, &block) if block
        @state[:web_pages] << web_page
      end
      web_page_info
    end

    def report_service_info
      return unless(in_issue && has_text)
      return unless @state[:web_site]
      return unless @state[:response_headers]
      banner = @state[:response_headers]["server"]
      return unless banner
      service = @state[:web_site].service
      return unless service.info.to_s.empty?
      service_info = {
        :host => service.host,
        :port => service.port,
        :proto => service.proto,
        :info => banner
      }
      db_report(:service, service_info)
    end

    def record_request_and_response
      return unless(in_issue && has_text)
      return unless @state[:web_site].present?
      really_original_traffic = unindent_and_crlf(@text)
      request_headers, request_body, response_headers, response_body = really_original_traffic.split(/\r\n\r\n/)
      return unless(request_headers && response_headers)
      req_header = Rex::Proto::Http::Packet::Header.new
      res_header = Rex::Proto::Http::Packet::Header.new
      req_header.from_s request_headers.lstrip
      res_header.from_s response_headers.lstrip
      if response_body.to_s.empty?
        response_body = ''
      end
      @state[:request_headers] = req_header
      @state[:request_body] = request_body.lstrip
      @state[:response_headers] = res_header
      @state[:response_body] = response_body.lstrip
    end

    # Appscan tab-indents which makes parsing a little difficult. They
    # also don't record CRLFs, just LFs.
    def unindent_and_crlf(text)
      second_line = text.split(/\r*\n/)[1]
      indent_level = second_line.size - second_line.lstrip.size
      unindented_text_lines = []
      text.split(/\r*\n/).each do |line|
        if line =~ /^\t{#{indent_level}}/
          unindented_line = line[indent_level,line.size]
          unindented_text_lines << unindented_line
        else
          unindented_text_lines << line
        end
      end
      unindented_text_lines.join("\r\n")
    end

    def record_risk
      return unless(in_issue && has_text)
      @state[:issue] ||= {}
      @state[:issue][:risk] = map_severity_to_risk
    end

    def map_severity_to_risk
      case @text.to_s.downcase
      when "high"   ; 5
      when "medium" ; 3
      when "low"    ; 1
      else          ; 0
      end
    end

    # TODO
    def record_issue
      return unless in_issue
      return unless @report_data[:issue].kind_of? Hash
      return unless @state[:web_site]
      return if @state[:issue]["Noise"].to_s.downcase == "true"
    end

    def collect_issue(attrs)
      return unless in_issue
      @state[:issue] = {}
      @state[:issue].merge! attr_hash(attrs)
    end

    def report_web_site(&block)
      return unless @state[:uri]
      uri = @state[:uri]
      hostname = uri.host # Assume the first one is the real hostname
      address = resolve_issue_url_address(uri)
      return unless address
      unless @resolv_cache.values.include? address
        db.emit(:address, address, &block) if block
      end
      port = resolve_port(uri)
      return unless port
      scheme = uri.scheme
      return unless scheme
      web_site_info = {:workspace => @args[:wspace]}
      web_site_info[:vhost] = hostname
      service_obj = check_for_existing_service(address,port)
      if service_obj
        web_site_info[:service] = service_obj
      else
        web_site_info[:host] = address
        web_site_info[:port] = port
        web_site_info[:ssl] = scheme == "https"
      end
      web_site_obj = db_report(:web_site, web_site_info)
      @state[:web_sites] ||= []
      unless @state[:web_sites].include? web_site_obj
        url = "#{uri.scheme}://#{uri.host}:#{uri.port}"
        db.emit(:web_site, url, &block) if block
        db.report_import_note(@args[:wspace], web_site_obj.service.host)
        @state[:web_sites] << web_site_obj
      end
      @state[:service] = service_obj || web_site_obj.service
      @state[:host] = (service_obj || web_site_obj.service).host
      @state[:web_site] = web_site_obj
    end

    def check_for_existing_service(address,port)
      db.get_service(@args[:wspace],address,"tcp",port)
    end

    def resolve_port(uri)
      @state[:port] = uri.port
      unless @state[:port]
        @parse_warnings << "Could not determine a port for '#{@state[:scan_name]}'"
      end
      return @state[:port]
    end

    def resolve_address(host)
      return @resolv_cache[host] if @resolv_cache[host]
      address = Rex::Socket.resolv_to_dotted(host) rescue nil
      @resolv_cache[host] = address
      if address
        block = @block
        db.emit(:address, address, &block) if block
      end
      return address
    end

    # Alias this
    def resolve_issue_url_address(uri)
      if uri.host
        address = resolve_address(uri.host)
        unless address
          @parse_warnings << "Could not resolve address for '#{uri.host}', skipping."
        end
      else
        @parse_warnings << "Could not determine a host for this import."
      end
      address
    end

    def handle_parse_warnings(&block)
      return if @parse_warnings.empty?
      @parse_warnings.each do |pwarn|
        db.emit(:warning, pwarn, &block) if block
      end
    end

    def record_url
      return unless in_issue
      return unless has_text
      uri = URI.parse(@text) rescue nil
      return unless uri
      @state[:uri] = uri
    end

    def in_issue
      return false unless in_tag("Issue")
      return false unless in_tag("Issues")
      return false unless in_tag("XmlReport")
      return true
    end

    def has_text
      return false unless @text
      return false if @text.strip.empty?
      @text = @text.strip
    end

  end

end
end

