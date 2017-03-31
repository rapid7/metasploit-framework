# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
  module Parser
    # If Nokogiri is available, define Masscan document class.
    load_nokogiri && class MasscanDocument < Nokogiri::XML::SAX::Document

    include NokogiriDocMixin

    def determine_port_state(v)
      case v
      when "open"
        Msf::ServiceState::Open
      when "closed"
        Msf::ServiceState::Closed
      when "filtered"
        Msf::ServiceState::Filtered
      else
        Msf::ServiceState::Unknown
      end
    end

    # Triggered every time a new element is encountered. We keep state
    # ourselves with the @state variable, turning things on when we
    # get here (and turning things off when we exit in end_element()).
    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block
      @state[:current_tag][name] = true
      case name
      when "address"
        record_address(attrs)
      when "port"
        record_port(attrs)
      when "state"
        # record host stats as up, masscan only includes active hosts
        record_host_status(attrs)
        record_port_state(attrs)
      end
    end

    # When we exit a tag, this is triggered.
    def end_element(name=nil)
      block = @block
      case name
      when "port"
        collect_port_data
        @state[:port] = {}
      when "host" # Roll everything up now
        collect_host_data
        host_object = report_host &block
        if host_object
          db.report_import_note(@args[:wspace],host_object)
          report_services(host_object,&block)
        end
        @state.delete_if {|k| k != :current_tag}
        @report_data = {:wspace => @args[:wspace]}
      end
      @state[:current_tag].delete name
    end

    def record_port_state(attrs)
      return unless in_tag("host")
      return unless in_tag("port")
      temp_hash = attr_hash(attrs)
      @state[:port] = @state[:port].merge(temp_hash)
    end

    def record_port(attrs)
      return unless in_tag("host")
      @state[:port] ||= {}
      svc = attr_hash(attrs)
      @state[:port] = @state[:port].merge(svc)
    end

    def record_host_status(attrs)
      return unless in_tag("host")
      @state[:host_alive] = TRUE
    end

    def record_address(attrs)
      return unless in_tag("host")
      @state[:addresses] ||= {}
      address = nil
      type = nil
      attrs.each do |k,v|
        if k == "addr"
          address = v
        elsif k == "addrtype"
          type = v
        end
      end
      @state[:addresses][type] = address
    end
    
    def collect_host_data
      if @state[:host_alive]
        @report_data[:state] = Msf::HostState::Alive
      else
        @report_data[:state] = Msf::HostState::Dead
      end
      if @state[:addresses]
        if @state[:addresses].has_key? "ipv4"
          @report_data[:host] = @state[:addresses]["ipv4"]
        elsif @state[:addresses].has_key? "ipv6"
          @report_data[:host] = @state[:addresses]["ipv6"]
        end
      end
    end

    def collect_port_data
      # masscan port data in tag port
      return unless in_tag("port")
      @report_data[:ports] ||= []
      port_hash = {}
      extra = []
      @state[:port].each do |k,v|
        case k
        when "protocol"
          port_hash[:proto] = v
        when "portid"
          port_hash[:port] = v
        when "state"
          port_hash[:state] = determine_port_state(v)
        when "reason"
          port_hash[:reason] = v
        end
      end
      # Skip localhost port results when they're unknown
      if( port_hash[:reason] == "localhost-response" &&
          port_hash[:state] == Msf::ServiceState::Unknown )
        @report_data[:ports]
      else
        @report_data[:ports] << port_hash
      end
    end
    def report_host(&block)
      if host_is_okay
        scripts = @report_data.delete(:scripts) || []
        host_object = db_report(:host, @report_data.merge( :workspace => @args[:wspace] ) )
        db.emit(:address,@report_data[:host],&block) if block

        scripts.each do |script|
          script.each_pair do |k,v|
            ntype =
            nse_note = {
              :workspace => host_object.workspace,
              :host => host_object,
              :type => "masscan.nse.#{k}.host",
              :data => { 'output' => v },
              :update => :unique_data
            }
            db_report(:note, nse_note)
          end
        end
        host_object
      end
    end

    def report_services(host_object,&block)
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:ports]
      return if @report_data[:ports].empty?
      reported = []
      @report_data[:ports].each do |svc|
        scripts = svc.delete(:scripts) || []
        svc_obj = db_report(:service, svc.merge(:host => host_object))
        scripts.each do |script|
          script.each_pair do |k,v|
            ntype =
            nse_note = {
              :workspace => host_object.workspace,
              :host => host_object,
              :service => svc_obj,
              :type => "masscan.nse.#{k}." + (svc[:proto] || "tcp") +".#{svc[:port]}",
              :data => { 'output' => v },
              :update => :unique_data
            }
            db_report(:note, nse_note)
          end
        end
        reported << svc_obj
      end
      reported
    end

  end

end
end

