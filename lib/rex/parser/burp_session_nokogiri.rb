# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
  module Parser

    # If Nokogiri is available, define Burp Session document class.
    #
    # Burp Session XML files actually provide a lot, but since it also
    # provides the originating url, we can pull most of the detail from
    # the URI object.
    load_nokogiri && class BurpSessionDocument < Nokogiri::XML::SAX::Document

    include NokogiriDocMixin

    # The resolver prefers your local /etc/hosts (or windows equiv), but will
    # fall back to regular DNS. It retains a cache for the import to avoid
    # spamming your network with DNS requests.
    attr_reader :resolv_cache

    # Since we try to resolve every time we hit a new web page, need to
    # hang on to our misses. Presume that it's a permanent enough failure
    # that it won't get fixed during this particular import
    attr_reader :missed_cache

    # If name resolution of the host fails out completely, you will not be
    # able to import that Scan task. Other scan tasks in the same report
    # should be unaffected.
    attr_reader :parse_warning

    def start_document
      @parse_warnings = []
      @parse_warned = []
      @resolv_cache = {}
      @missed_cache = []
    end

    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block
      @state[:current_tag][name] = true
      case name
      when "host", "port", "protocol", "path"
        @state[:has_text] = true
      when "status"
        @state[:has_text] = true
      when "response"
        @state[:has_text] = true
      end
    end

    def end_element(name=nil)
      block = @block
      case name
      when "item" # Wrap up this item, but keep resolved web sites
        collect_uri
        report_web_site(&block)
        handle_parse_warnings(&block)
        report_web_page(&block)
        report_web_service_info
        report_web_host_info
        # Reset the state once we close a host
        @state = @state.select {|k| [:current_tag, :web_sites].include? k}
      when "host"
        @state[:has_text] = false
        collect_host
        @text = nil
      when "port"
        @state[:has_text] = false
        collect_port
        @text = nil
      when "protocol"
        @state[:has_text] = false
        collect_protocol
        @text = nil
      when "path"
        @state[:has_text] = false
        collect_path_and_query
        @text = nil
      when "status"
        @state[:has_text] = false
        collect_status
        @text = nil
      when "response"
        @state[:has_text] = false
        collect_response
        @text = nil
      end
      @state[:current_tag].delete name
    end

    def collect_host
      return unless in_item
      return unless has_text
      @state[:host] = @text
    end

    def collect_port
      return unless in_item
      return unless has_text
      return unless @text.to_i.to_s == @text.to_s
      @state[:port] = @text.to_i
    end

    def collect_protocol
      return unless in_item
      return unless has_text
      @state[:protocol] = @text
    end

    def collect_path_and_query
      return unless in_item
      return unless has_text
      path,query = @text.split(/\?+/,2)
      return unless path
      if query
        @state[:query] = "?#{query}" # Can be nil
      end
      if path =~ /https?:[\x5c\x2f][\x5c\x2f]+[^\x5c\x2f][^\x5c\x2f]+([^?]+)/n
        real_path = "/#{$1}"
      else
        real_path = path
      end
      @state[:path] = real_path
    end

    def collect_status
      return unless in_item
      return unless has_text
      return unless @text.to_i.to_s == @text
      @state[:status] = @text.to_i
    end

    def collect_uri
      return unless in_item
      return unless @state[:host]
      return unless @state[:port]
      return unless @state[:protocol]
      return unless @state[:path]
      url = @state[:protocol].to_s
      url << "://"
      url << @state[:host].to_s
      url << ":"
      url << @state[:port].to_s
      url << @state[:path]
      if @state[:query]
        url << "?"
        url << @state[:query]
      end
      @state[:uri] = URI.parse(url) rescue nil
    end

    def report_web_host_info
      return unless @state[:web_site]
      return unless @state[:uri].kind_of? URI::HTTP
      return unless @state[:web_site].service.host.name.to_s.empty?
      host_info = {:workspace => @args[:wspace]}
      host_info[:address] = @state[:web_site].service.host.address
      host_info[:name] = @state[:uri].host
      db_report(:host, host_info)
    end

    def report_web_service_info
      return unless @state[:web_site]
      return unless @state[:service_info]
      return unless @state[:web_site].service.info.to_s.empty?
      service_info = {}
      service_info[:host] = @state[:web_site].service.host
      service_info[:port] = @state[:web_site].service.port
      service_info[:proto] = @state[:web_site].service.proto
      service_info[:info] = @state[:service_info]
      db_report(:service, service_info)
    end

    def report_web_page(&block)
      return unless @state[:uri].kind_of? URI::HTTP
      return unless @state[:status]
      return unless @state[:web_site]
      return unless @state[:response_headers].kind_of? Hash
      headers = {}
      @state[:response_headers].each do |k,v|
        headers[k.to_s.downcase] ||= []
        headers[k.to_s.downcase] << v
      end
      if headers["server"].kind_of? Array
        @state[:service_info] = headers["server"].first
      end
      return unless @state[:response_body]
      web_page_info = {:workspace => @args[:wspace]}
      web_page_info[:web_site] = @state[:web_site]
      web_page_info[:code] = @state[:status]
      web_page_info[:path] = @state[:uri].path
      web_page_info[:headers] = headers
      web_page_info[:body] = @state[:response_body]
      web_page_info[:query] = @state[:uri].query
      url = @state[:uri].to_s.gsub(/\?.*/,"")
      db.emit(:web_page, url, &block) if block
      db_report(:web_page, web_page_info)
    end

    def report_web_site(&block)
      return unless @state[:uri].kind_of? URI::HTTP
      vhost = @state[:uri].host
      web_site_info = {:workspace => @args[:wspace]}
      web_site_info[:vhost] = vhost
      address = resolve_vhost_address(@state[:uri])
      return unless address
      web_site_info[:host] = address
      web_site_info[:port] = @state[:uri].port
      web_site_info[:ssl]  = @state[:uri].kind_of? URI::HTTPS
      web_site_obj = db_report(:web_site, web_site_info)
      return unless web_site_obj
      @state[:web_sites] ||= []
      url = "#{@state[:uri].scheme}://#{@state[:uri].host}:#{@state[:uri].port}"
      unless @state[:web_sites].include? web_site_obj
        db.emit(:web_site, url, &block)
        @state[:web_sites] << web_site_obj
      end
      @state[:web_site] = web_site_obj
    end

    def collect_response
      return unless in_item
      return unless has_text
      response_text = @text.dup
      response_header_text,response_body_text = response_text.split(/\r*\n\r*\n/n,2)
      return unless response_header_text
      response_header = Rex::Proto::Http::Packet::Header.new
      response_header.from_s response_header_text
      @state[:response_headers] = response_header
      @state[:response_body] = response_body_text
    end

    def in_item
      return false unless in_tag("item")
      return false unless in_tag("items")
      return true
    end

    def has_text
      return false unless @text
      return false if @text.strip.empty?
      @text = @text.strip
    end

    def handle_parse_warnings(&block)
      return if @parse_warnings.empty?
      return unless block
      @parse_warnings.each_with_index do |pwarn,i|
        unless @parse_warned.include? i
          db.emit(:warning, pwarn, &block)
          @parse_warned << i
        end
      end
    end

    def resolve_address(host)
      return @resolv_cache[host] if @resolv_cache[host]
      return false if @missed_cache.include? host
      address = Rex::Socket.resolv_to_dotted(host) rescue nil
      @resolv_cache[host] = address
      if address
        block = @block
        db.emit(:address, address, &block) if block
      else
        @missed_cache << host
      end
      return address
    end

    # Alias this
    def resolve_vhost_address(uri)
      if uri.host
        address = resolve_address(uri.host)
        case address
        when false
          return false
        when nil
          @parse_warnings << "Could not resolve address for '#{uri.host}', skipping."
        end
      else
        @parse_warnings << "Could not determine a host for this import."
      end
      address
    end

  end

end
end

