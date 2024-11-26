# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
module Parser

  # If Nokogiri is available, define OpenVas document class.
  load_nokogiri && class OpenVASDocument < Nokogiri::XML::SAX::Document

  include NokogiriDocMixin

  # ourselves with the @state variable, turning things on when we
  # get here (and turning things off when we exit in end_element()).
  def start_element(name=nil,attrs=[])
    attrs = normalize_attrs(attrs)
    block = @block
    @state[:current_tag][name] = true

    unless @text.nil?
      @state[:text_backup] = @text
      @text = nil
    end

    case name
    when "host"
      @state[:has_text] = true
    when 'ref'
      ref_type = ''
      ref_id = ''
      if defined?(attrs) && attrs.kind_of?(Array)
        attrs.each do |attr|
          next if !defined?(attr) || !attr.kind_of?(Array) || attr.length != 2
          if defined?(attr[0]) && defined?(attr[1]) && attr[0] == 'type'
            ref_type = attr[1]
          end
          if defined?(attr[0]) && defined?(attr[1]) && attr[0] == 'id'
            ref_id = attr[1]
          end
        end
      end
      if in_tag('result') && in_tag('nvt') && in_tag('refs') &&
          !ref_type.empty? && !ref_type.empty?
        case ref_type.upcase
        when 'CVE'
          @state[:ref_cve] = [] if @state[:ref_cve].nil?
          @state[:ref_cve].append(ref_id.strip)
        when 'URL'
          @state[:ref_url] = [] if @state[:ref_url].nil?
          @state[:ref_url].append(ref_id.strip)
        when 'DFN-CERT'
          if defined?(@args[:options][:openvas_dfn]) && @args[:options][:openvas_dfn]
            @state[:ref_dfn] = [] if @state[:ref_dfn].nil?
            @state[:ref_dfn].append(ref_id.strip)
          end
        when 'CERT-BUND'
          if defined?(@args[:options][:openvas_cert]) && @args[:options][:openvas_cert]
            @state[:ref_cb] = [] if @state[:ref_cb].nil?
            @state[:ref_cb].append(ref_id.strip)
          end
        end
      end
    end
  end

  # When we exit a tag, this is triggered.
  def end_element(name=nil)
    block = @block
    case name
    when 'name'
      if in_tag('result')
        @state[:has_text] = true
        @state[:vuln_name] = @text.strip if @text
      end
    when 'description'
      if in_tag('result')
        @state[:has_text] = true
        @state[:vuln_desc] = @text.strip if @text
      end
    when 'bid'
      if in_tag('result') && in_tag('nvt')
        @state[:has_text] = true
        @state[:bid] = @text.strip if @text
      end
    when 'cve'
      if in_tag('result') && in_tag('nvt')
        @state[:has_text] = true
        @state[:cves] = @text.strip if @text
      end
    when 'risk_factor'
      if in_tag('result') && in_tag('nvt')
        #we do this to clean out the buffer so to speak
        #if we don't set text to nil now, the text will show up later
        @state[:has_text] = true
      end
    when 'cvss_base'
      if in_tag('result')  && in_tag('nvt')
        @state[:has_text] = true
      end
    when 'subnet'
      @state[:has_text] = true
    when 'result'
      record_vuln
    when 'threat'
      @state[:has_text] = true if in_tag('ports') && in_tag('port')
    when 'host'
      if in_tag('result')
        @state[:has_text] = true
        @state[:host] = @text.strip if @text
      elsif in_tag('ports') && in_tag('port')
        @state[:has_text] = true
        @state[:host] = @text.strip if @text
      end
    when 'port'
      if in_tag('result')
        @state[:has_text] = true
        if @text
          if /^(?<p_num>\d{1,5})\/(?<p_proto>.+)\s\((?<p_name>.+)\)/ =~ @text
            @state[:name] = p_name.gsub(/iana: /i, '')
            @state[:port] = p_num
            @state[:proto] = p_proto
          elsif @text.index('(')
            @state[:proto] = @text.split('(')[1].split('/')[1].gsub(/\)/, '')
            @state[:port] = @text.split('(')[1].split('/')[0].gsub(/\)/, '')
          elsif @text.index('/')
            @state[:proto] = @text.split('/')[1].strip
            @state[:port] = @text.split('/')[0].strip
          else
            @state[:proto] = nil
            @state[:port] = nil
          end

          if @state[:port] && @state[:port] == 'general'
            @state[:proto] = nil
            @state[:port] = nil
          end
        end
      elsif in_tag('ports')
        if @text
          if /^(?<p_num>\d{1,5})\/(?<p_proto>.+)\s\((?<p_name>.+)\)/ =~ @text
            @state[:name] = p_name.gsub(/iana: /i, '')
            @state[:port] = p_num
            @state[:proto] = p_proto
            record_service if p_num
          elsif @text.index('(')
            @state[:name] = @text.split(' ')[0]
            @state[:port] = @text.split('(')[1].split('/')[0]
            @state[:proto] = @text.split('(')[1].split('/')[1].split(')')[0]
            record_service unless @state[:name].nil?
          elsif @text.index('/')
            @state[:port] = @text.split('/')[0].strip
            @state[:proto] = @text.split('/')[1].strip
            record_service unless @state[:port] == 'general'
          end
        end
      end
    when 'name'
      return if not in_tag('result')
      @state[:has_text] = true
    end

    if @state[:text_backup]
      @text = @state[:text_backup]
      @state[:text_backup] = nil
    else
      @text = nil
    end

    @state[:current_tag].delete name
  end

  def record_vuln
    if (@state[:cves] and @state[:cves] == "NOCVE")  and (@state[:bid] and @state[:bid] == "NOBID")
      return
    end

    references = []
    if @state[:cves] and @state[:cves] != "NOCVE" and !@state[:cves].empty?
      @state[:cves].split(',').each do |cve|
        references.append({ :source => "CVE", :value => cve})
      end
    end
    if @state[:bid] and @state[:bid] != "NOBID" and !@state[:bid].empty?
      @state[:bid].split(',').each do |bid|
        references.append({ :source => "BID", :value => bid})
      end
    end
    if @state[:ref_cve] && @state[:ref_cve].kind_of?(Array)
      @state[:ref_cve].each do |cve|
        references.append({ :source => "CVE", :value => cve.dup}) if !cve.empty?
      end
      @state[:ref_cve].clear
    end
    if @state[:ref_url] && @state[:ref_url].kind_of?(Array)
      @state[:ref_url].each do |url|
        references.append({ :source => "URL", :value => url.dup}) if !url.empty?
      end
      @state[:ref_url].clear
    end
    if @state[:ref_cb] && @state[:ref_cb].kind_of?(Array)
      @state[:ref_cb].each do |cb|
        references.append({ :source => "CB", :value => cb.dup}) if !cb.empty?
      end
      @state[:ref_cb].clear
    end
    if @state[:ref_dfn] && @state[:ref_dfn].kind_of?(Array)
      @state[:ref_dfn].each do |dfn|
        references.append({ :source => "DFN-CERT", :value => dfn.dup}) if !dfn.empty?
      end
      @state[:ref_dfn].clear
    end

    vuln_info = {}
    vuln_info[:host] = @state[:host]
    vuln_info[:refs] = normalize_references(references)
    vuln_info[:name] = @state[:vuln_name]
    vuln_info[:info] = @state[:vuln_desc]
    vuln_info[:port] = @state[:port]
    vuln_info[:proto] = @state[:proto]
    vuln_info[:workspace] = @args[:workspace]
    db_report(:vuln, vuln_info)
  end

  def record_service
    service_info = {}
    service_info[:host] = @state[:host]
    service_info[:name] = @state[:name]
    service_info[:port] = @state[:port]
    service_info[:proto] = @state[:proto]
    service_info[:workspace] = @args[:workspace]

    db_report(:service, service_info)

    host_info = {}
    host_info[:host] = @state[:host]
    host_info[:workspace] = @args[:workspace]

    db_report(:host, host_info)
  end
end
end
end

