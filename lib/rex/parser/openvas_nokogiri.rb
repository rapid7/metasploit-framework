# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
module Parser

  # If Nokogiri is available, define OpenVAS document class.
  load_nokogiri && class OpenVASDocument < Nokogiri::XML::SAX::Document

  include NokogiriDocMixin

  # ourselves with the @state variable, turning things on when we
  # get here (and turning things off when we exit in end_element()).
  def start_element(name=nil,attrs=[])
    attrs = normalize_attrs(attrs)
    block = @block
    @state[:current_tag][name] = true
    case name
    when "host"
      @state[:has_text] = true
    end
  end

  # When we exit a tag, this is triggered.
  def end_element(name=nil)
    block = @block
    case name
    when "name"
      return if not in_tag("result")
      @state[:has_text] = true
      @state[:vuln_name] = @text.strip if @text
      @text = nil
    when "description"
      @state[:has_text] = true
      @state[:vuln_desc] = @text.strip if @text
      @text = nil
    when "bid"
      return if not in_tag("result")
      return if not in_tag("nvt")
      @state[:has_text] = true
      @state[:bid] = @text.strip if @text
      @text = nil
    when "cve"
      return if not in_tag("result")
      return if not in_tag("nvt")
      @state[:has_text] = true
      @state[:cves] = @text.strip if @text
      @text = nil
    when "risk_factor"
      return if not in_tag("result")
      return if not in_tag("nvt")

      #we do this to clean out the buffer so to speak
      #if we don't set text to nil now, the text will show up later
      @state[:has_text] = true
      @text = nil
    when "cvss_base"
      return if not in_tag("result")
      return if not in_tag("nvt")
      @state[:has_text] = true
      @text = nil
    when "subnet"
      @state[:has_text] = true
      @text = nil
    when "result"
      return if not in_tag("results")
      record_vuln
    when "threat"
      return if not in_tag("ports")
      return if not in_tag("port")
      @state[:has_text] = true

      if not @text.index('(')
        @state[:name] = nil
        @state[:port] = nil
        @state[:proto] = nil
        @text = nil
        return
      end

      @state[:name] = @text.split(' ')[0] if @text
      @state[:port] = @text.split('(')[1].split('/')[0] if @text
      @state[:proto] = @text.split('(')[1].split('/')[1].split(')')[0] if @text

      @text = nil
    when "host"
      if in_tag('result')
        @state[:has_text] = true
        @state[:host] = @text.strip if @text
        @text = nil
      elsif in_tag('ports')
        return if not in_tag('port')
        @state[:has_text] = true
        @state[:host] = @text.strip if @text
        @text = nil
      end
    when "port"
      if in_tag('result')
        @state[:has_text] = true
        if not @text.index('(')
          @state[:proto] = nil
          @state[:port] = nil
          @text = nil
          return
        end
        @state[:proto] = @text.split('(')[0].strip if @text
        @state[:port] = @text.split('(')[1].split('/')[0].gsub(/\)/, '') if @text
        @text = nil
      elsif in_tag('ports')
        record_service
      end
    when "name"
      return if not in_tag("result")
      @state[:has_text] = true
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

        db_report(:vuln, vuln_info)
      end
    end
  end

  def record_service
    return if not @state[:name]

    service_info = {}
    service_info[:host] = @state[:host]
    service_info[:name] = @state[:name]
    service_info[:port] = @state[:port]
    service_info[:proto] = @state[:proto]

    db_report(:service, service_info)

    host_info = {}
    host_info[:host] = @state[:host]

    db_report(:host, host_info)
  end
end
end
end

