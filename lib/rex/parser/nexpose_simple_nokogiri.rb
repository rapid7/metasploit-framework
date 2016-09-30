# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
  module Parser

    # If Nokogiri is available, define Nexpose document class.
    load_nokogiri && class NexposeSimpleDocument < Nokogiri::XML::SAX::Document

    include NokogiriDocMixin

    attr_reader :text

    # Triggered every time a new element is encountered. We keep state
    # ourselves with the @state variable, turning things on when we
    # get here (and turning things off when we exit in end_element()).
    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block
      @state[:current_tag][name] = true
      case name
      when "device"
        record_device(attrs)
      when "service"
        record_service(attrs)
      when "fingerprint"
        record_service_fingerprint(attrs)
        record_host_fingerprint(attrs)
      when "description"
        @state[:has_text] = true
        record_host_fingerprint_data(name,attrs)
      when "vendor", "family", "product", "version", "architecture"
        @state[:has_text] = true
        record_host_fingerprint_data(name,attrs)
      when "vulnerability"
        record_service_vuln(attrs)
        record_host_vuln(attrs)
      when "id"
        @state[:has_text] = true
        record_service_vuln_id(attrs)
        record_host_vuln_id(attrs)
      end
    end

    # When we exit a tag, this is triggered.
    def end_element(name=nil)
      block = @block
      case name
      when "device" # Wrap it up
        collect_device_data
        host_object = report_host &block
        report_services(host_object)
        report_host_fingerprint(host_object)
        report_vulns(host_object)
        # Reset the state once we close a host
        @state.delete_if {|k| k != :current_tag}
        @report_data = {:wspace => @args[:wspace]}
      when "description"
        @state[:has_text] = false
        collect_service_fingerprint_description
        collect_host_fingerprint_data(name)
        @text = nil
      when "vendor", "family", "product", "version", "architecture"
        @state[:has_text] = false
        collect_host_fingerprint_data(name)
        @text = nil
      when "service"
        collect_service_data
      when "id"
        @state[:has_text] = false
        collect_service_vuln_id
        collect_host_vuln_id
        @text = nil
      when "vulnerability"
        collect_service_vuln
        collect_host_vuln
        @state[:references] = nil
      end
      @state[:current_tag].delete name
    end

    def report_vulns(host_object)
      vuln_count = 0
      block = @block
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:vulns]
      @report_data[:vulns].each do |vuln|
        if vuln[:refs]
          vuln[:refs] << vuln[:name]
        else
          vuln[:refs] = [vuln[:name]]
        end
        vuln[:refs].uniq!
        data = {
          :workspace => host_object.workspace,
          :host => host_object,
          :name => vuln[:name],
          :info => vuln[:info],
          :refs => vuln[:refs]
        }
        if vuln[:port] && vuln[:proto]
          data[:port] = vuln[:port]
          data[:proto] = vuln[:proto]
        end
        db_report(:vuln,data)
      end

    end

    def collect_host_vuln_id
      return unless in_tag("device")
      return unless in_tag("vulnerability")
      return if in_tag("service")
      return unless @state[:host_vuln_id]
      @state[:references] ||= []
      ref = normalize_ref( @state[:host_vuln_id]["type"], @text )
      @state[:references] << ref if ref
      @state[:host_vuln_id] = nil
      @text = nil
    end

    def collect_service_vuln_id
      return unless in_tag("device")
      return unless in_tag("vulnerability")
      return unless in_tag("service")
      return unless @state[:service_vuln_id]
      @state[:references] ||= []
      ref = normalize_ref( @state[:service_vuln_id]["type"], @text )
      @state[:references] << ref if ref
      @state[:service_vuln_id] = nil
      @text = nil
    end

    def collect_service_vuln
      return unless in_tag("device")
      return unless in_tag("vulnerability")
      return unless in_tag("service")
      @report_data[:vulns] ||= []
      return unless actually_vulnerable(@state[:service_vuln])
      return if @state[:service]["port"].to_i == 0
      vid = @state[:service_vuln]["id"].to_s.downcase
      vuln = {
        :name => "NEXPOSE-#{vid}",
        :info => vid,
        :refs => @state[:references],
        :port => @state[:service]["port"].to_i,
        :proto => @state[:service]["protocol"]
      }
      @report_data[:vulns] << vuln
    end

    def collect_host_vuln
      return unless in_tag("vulnerability")
      return unless in_tag("device")
      return if in_tag("service")
      @report_data[:vulns] ||= []
      return unless actually_vulnerable(@state[:host_vuln])
      vid = @state[:host_vuln]["id"].to_s.downcase
      vuln = {
        :name => "NEXPOSE-#{vid}",
        :info => vid,
        :refs => @state[:references]
      }
      @report_data[:vulns] << vuln
    end

    def record_host_vuln_id(attrs)
      return unless in_tag("device")
      return if in_tag("service")
      @state[:host_vuln_id] = attr_hash(attrs)
    end

    def record_host_vuln(attrs)
      return unless in_tag("device")
      return if in_tag("service")
      @state[:host_vuln] = attr_hash(attrs)
    end

    def record_service_vuln_id(attrs)
      return unless in_tag("device")
      return unless in_tag("service")
      @state[:service_vuln_id] = attr_hash(attrs)
    end

    def record_service_vuln(attrs)
      return unless in_tag("device")
      return unless in_tag("service")
      @state[:service_vuln] = attr_hash(attrs)
    end

    def actually_vulnerable(vuln)
      vuln_result = vuln["resultCode"]
      vuln_result =~ /^V[VE]$/
    end

    def record_device(attrs)
      attrs.each do |k,v|
        next unless k == "address"
        @state[:address] = v
      end
    end

    def record_host_fingerprint(attrs)
      return unless in_tag("device")
      return if in_tag("service")
      @state[:host_fingerprint] = attr_hash(attrs)
    end

    def collect_device_data
      return unless in_tag("device")
      @report_data[:host] = @state[:address]
      @report_data[:state] = Msf::HostState::Alive # always
    end

    def record_host_fingerprint_data(name, attrs)
      return unless in_tag("device")
      return if in_tag("service")
      return unless in_tag("fingerprint")
      @state[:host_fingerprint] ||= {}
      @state[:host_fingerprint].merge! attr_hash(attrs)
    end

    def collect_host_fingerprint_data(name)
      return unless in_tag("device")
      return if in_tag("service")
      return unless in_tag("fingerprint")
      return unless @text
      @report_data[:host_fingerprint] ||= {}
      @report_data[:host_fingerprint].merge!(@state[:host_fingerprint])
      @report_data[:host_fingerprint][name] = @text.to_s.strip
      @text = nil
    end

    def report_host(&block)
      if host_is_okay
        db.emit(:address,@report_data[:host],&block) if block
        host_object = db_report(:host, @report_data.merge(
          :workspace => @args[:wspace] ) )
        if host_object
          db.report_import_note(host_object.workspace, host_object)
        end
        host_object
      end
    end

    def report_host_fingerprint(host_object)
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:host_fingerprint].kind_of? Hash
      @report_data[:host_fingerprint].reject! {|k,v| v.nil? || v.empty?}
      return if @report_data[:host_fingerprint].empty?
      note = {
        :workspace => host_object.workspace,
        :host => host_object,
        :type => "host.os.nexpose_fingerprint"
      }
      data = {
        :desc => @report_data[:host_fingerprint]["description"],
        :vendor => @report_data[:host_fingerprint]["vendor"],
        :family => @report_data[:host_fingerprint]["family"],
        :product => @report_data[:host_fingerprint]["product"],
        :version => @report_data[:host_fingerprint]["version"],
        :arch => @report_data[:host_fingerprint]["architecture"]
      }
      db_report(:note, note.merge(:data => data))
    end

    def record_service(attrs)
      return unless in_tag("device")
      @state[:service] = attr_hash(attrs)
    end

    def record_service_fingerprint(attrs)
      return unless in_tag("device")
      return unless in_tag("service")
      @state[:service][:fingerprint] = attr_hash(attrs)
    end

    def collect_service_data
      return unless in_tag("device")
      port_hash = {}
      @report_data[:ports] ||= []
      @state[:service].each do |k,v|
        case k
        when "protocol"
          port_hash[:proto] = v
        when "port"
          port_hash[:port] = v
        when "name"
          sname = v.to_s.downcase.split("(")[0].strip
          if sname == "<unknown>"
            port_hash[:name] = nil
          else
            port_hash[:name] = db.nmap_msf_service_map(sname)
          end
        end
      end
      if @state[:service_fingerprint]
        port_hash[:info] = "#{@state[:service_fingerprint]}"
      end
      @report_data[:ports] << port_hash.clone
      @state.delete :service_fingerprint
      @state.delete :service
      @report_data[:ports]
    end

    def collect_service_fingerprint_description
      return unless in_tag("device")
      return unless in_tag("service")
      return unless in_tag("fingerprint")
      return unless @text
      @state[:service_fingerprint] = @text.to_s.strip
      @text = nil
    end

    def report_services(host_object)
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:ports]
      return if @report_data[:ports].empty?
      reported = []
      @report_data[:ports].each do |svc|
        reported << db_report(:service, svc.merge(:host => host_object))
      end
      reported
    end

  end

end
end

