# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
  module Parser

    # If Nokogiri is available, define Template document class.
    load_nokogiri && class MbsaDocument < Nokogiri::XML::SAX::Document

    include NokogiriDocMixin

    # Triggered every time a new element is encountered. We keep state
    # ourselves with the @state variable, turning things on when we
    # get here (and turning things off when we exit in end_element()).
    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block
      @state[:current_tag][name] = true
      case name
      when "SecScan"
        record_host(attrs)
      when "IP" # TODO: Check to see if IPList/IP is useful to import
      when "Check" # A list of MBSA checks. They have an ID and a Name.
        record_check(attrs)
      when "Advice" # Check advice. Free form text about the check
        @state[:has_text] = true
      when "Detail" # Check/Detail is where missing fixes are.
        record_detail(attrs)
      when "UpdateData" # Info about installed/missing hotfixes
        record_updatedata(attrs)
      when "Title" # MSB Title
        @state[:has_text] = true
      when "InformationURL" # Only use this if we don't have a Bulletin ID
        @state[:has_text] = true
      end
    end

    # This breaks xml-encoded characters, so need to append
    def characters(text)
      return unless @state[:has_text]
      @text ||= ""
      @text << text
    end

    # When we exit a tag, this is triggered.
    def end_element(name=nil)
      block = @block
      case name
      when "SecScan" # Wrap it up
        collect_host_data
        host_object = report_host &block
        if host_object
          db.report_import_note(@args[:workspace],host_object)
          report_fingerprint(host_object)
          report_vulns(host_object,&block)
        end
        # Reset the state once we close a host
        @state.delete_if {|k| k != :current_tag}
      when "Check"
        collect_check_data
      when "Advice"
        @state[:has_text] = false
        collect_advice_data
      when "Detail"
        collect_detail_data
      when "UpdateData"
        collect_updatedata
      when "Title"
        @state[:has_text] = false
        collect_title
      when "InformationURL"
        collect_url
        @state[:has_text] = false
      end
      @state[:current_tag].delete name
    end

    def report_fingerprint(host_object)
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:os_fingerprint]
      fp_note = @report_data[:os_fingerprint].merge(
        {
          :workspace => host_object.workspace,
          :host => host_object
      })
      db_report(:note, fp_note)
    end

    def collect_url
      return unless in_tag("References")
      return unless in_tag("UpdateData")
      return unless in_tag("Detail")
      return unless in_tag("Check")
      @state[:update][:url] = @text.to_s.strip
      @text = nil
    end

    def report_vulns(host_object, &block)
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:vulns]
      return if @report_data[:vulns].empty?
      @report_data[:vulns].each do |vuln|
        next unless vuln[:refs]
        if vuln[:refs].empty?
          next
        end
        if block
          db.emit(:vuln, ["Missing #{vuln[:name]}",1], &block) if block
        end
        db_report(:vuln, vuln.merge(:host => host_object))
      end
    end

    def collect_title
      return unless in_tag("SecScan")
      return unless in_tag("Check")
      collect_bulletin_title
      @text = nil
    end

    def collect_bulletin_title
      return unless @state[:check_state]["ID"] == 500.to_s
      return unless in_tag("UpdateData")
      return unless @state[:update]
      return if @text.to_s.strip.empty?
      @state[:update]["Title"] = @text.to_s.strip
    end

    def collect_updatedata
      return unless in_tag("SecScan")
      return unless in_tag("Check")
      return unless in_tag("Detail")
      collect_missing_update
      @state[:updates] = {}
    end

    def collect_missing_update
      return unless @state[:check_state]["ID"] == 500.to_s
      return if @state[:update]["IsInstalled"] == "true"
      @report_data[:missing_updates] ||= []
      this_update = {}
      this_update[:name] = @state[:update]["Title"].to_s.strip
      this_update[:refs] = []
      if @state[:update]["BulletinID"].empty?
        this_update[:refs] << "URL-#{@state[:update][:url]}"
      else
        this_update[:refs] << "MSB-#{@state[:update]["BulletinID"]}"
      end
      @report_data[:missing_updates] << this_update
    end

    # So far, just care about Host OS
    # There is assuredly more interesting things going on in here.
    def collect_advice_data
      return unless in_tag("SecScan")
      return unless in_tag("Check")
      collect_os_name
      @text = nil
    end

    def collect_os_name
      return unless @state[:check_state]["ID"] == 10101.to_s
      return unless @text
      return if @text.strip.empty?
      os_match = @text.match(/Computer is running (.*)/)
      return unless os_match
      os_info = os_match[1]
      os_vendor = os_info[/Microsoft/]
      os_family = os_info[/Windows/]
      os_version = os_info[/(XP|2000 Advanced Server|2000|2003|2008|SBS|Vista|7 .* Edition|7)/]
      if os_info
        @report_data[:os_fingerprint] = {}
        @report_data[:os_fingerprint][:type] = "host.os.mbsa_fingerprint"
        @report_data[:os_fingerprint][:data] = {
          :os_vendor => os_vendor,
          :os_family => os_family,
          :os_version => os_version,
          :os_accuracy => 100,
          :os_match => os_info.gsub(/\x2e$/n,"")
        }
      end
    end

    def collect_detail_data
      return unless in_tag("SecScan")
      return unless in_tag("Check")
      if @report_data[:missing_updates]
        @report_data[:vulns] = @report_data[:missing_updates]
      end
    end

    def collect_check_data
      return unless in_tag("SecScan")
      @state[:check_state] = {}
    end

    def collect_host_data
      return unless @state[:address]
      return if @state[:address].strip.empty?
      @report_data[:host] = @state[:address].strip
      if @state[:hostname] && !@state[:hostname].empty?
        @report_data[:name] = @state[:hostname]
      end
      @report_data[:state] = Msf::HostState::Alive
    end

    def report_host(&block)
      if host_is_okay
        db.emit(:address,@report_data[:host],&block) if block
        host_info = @report_data.merge(:workspace => @args[:workspace])
        db_report(:host, host_info)
      end
    end

    def record_updatedata(attrs)
      return unless in_tag("SecScan")
      return unless in_tag("Check")
      return unless in_tag("Detail")
      update_attrs = attr_hash(attrs)
      @state[:update] = attr_hash(attrs)
    end

    def record_host(attrs)
      host_attrs = attr_hash(attrs)
      @state[:address] = host_attrs["IP"]
      @state[:hostname] = host_attrs["Machine"]
    end

    def record_check(attrs)
      return unless in_tag("SecScan")
      @state[:check_state] = attr_hash(attrs)
    end

    def record_detail(attrs)
      return unless in_tag("SecScan")
      return unless in_tag("Check")
      @state[:detail_state] = attr_hash(attrs)
    end

    # We need to override the usual host_is_okay because MBSA apparently
    # doesn't report on open ports at all.
    def host_is_okay
      return false unless @report_data[:host]
      return false unless valid_ip(@report_data[:host])
      return false unless @report_data[:state] == Msf::HostState::Alive
      if @args[:blacklist]
        return false if @args[:blacklist].include?(@report_data[:host])
      end
      return true
    end

  end

end
end

