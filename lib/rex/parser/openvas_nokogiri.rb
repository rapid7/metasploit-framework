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
        if @text && @text.index('(')
          @state[:proto] = @text.split('(')[1].split('/')[1].gsub(/\)/, '')
          @state[:port] = @text.split('(')[1].split('/')[0].gsub(/\)/, '')
        elsif @text && @text.index('/')
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
      elsif in_tag('ports')
        if @text && @text.index('(')
          @state[:name] = @text.split(' ')[0]
          @state[:port] = @text.split('(')[1].split('/')[0]
          @state[:proto] = @text.split('(')[1].split('/')[1].split(')')[0]
          record_service unless @state[:name].nil?
        elsif @text && @text.index('/')
          @state[:port] = @text.split('/')[0]
          @state[:proto] = @text.split('/')[1]
          record_service unless @state[:port] == 'general'
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

    if @state[:cves] and @state[:cves] != "NOCVE" and !@state[:cves].empty?
      @state[:cves].split(',').each do |cve|
        vuln_info = {}
        vuln_info[:host] = @state[:host]
        vuln_info[:refs] = normalize_references([{ :source => "CVE", :value => cve}])
        vuln_info[:name] = @state[:vuln_name]
        vuln_info[:info] = @state[:vuln_desc]
        vuln_info[:port] = @state[:port]
        vuln_info[:proto] = @state[:proto]
        vuln_info[:workspace] = @args[:wspace]

        db_report(:vuln, vuln_info)
      end
    end
    if @state[:bid] and @state[:bid] != "NOBID" and !@state[:bid].empty?
      @state[:bid].split(',').each do |bid|
        vuln_info = {}
        vuln_info[:host] = @state[:host]
        vuln_info[:refs] = normalize_references([{ :source => "BID", :value => bid}])
        vuln_info[:name] = @state[:vuln_name]
        vuln_info[:info] = @state[:vuln_desc]
        vuln_info[:port] = @state[:port]
        vuln_info[:proto] = @state[:proto]
        vuln_info[:workspace] = @args[:wspace]

        db_report(:vuln, vuln_info)
      end
    end
  end

  def record_service
    service_info = {}
    service_info[:host] = @state[:host]
    service_info[:name] = @state[:name]
    service_info[:port] = @state[:port]
    service_info[:proto] = @state[:proto]
    service_info[:workspace] = @args[:wspace]

    db_report(:service, service_info)

    host_info = {}
    host_info[:host] = @state[:host]
    host_info[:workspace] = @args[:wspace]

    db_report(:host, host_info)
  end
end
end
end

