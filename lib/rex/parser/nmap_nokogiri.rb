# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

module Rex
  module Parser

    # If Nokogiri is available, define Nmap document class.
    load_nokogiri && class NmapDocument < Nokogiri::XML::SAX::Document

    include NokogiriDocMixin

    def determine_port_state(v)
      case v
      when "open"
        Msf::ServiceState::Open
      when "closed"
        Msf::ServiceState::Closed
      when "filtered"
        Msf::ServiceState::Filtered
      when "unknown"
        Msf::ServiceState::Unknown
      end
    end

    # Compare OS fingerprinting data
    def better_os_match(orig_hash,new_hash)
      return false unless new_hash.has_key? "accuracy"
      return true unless orig_hash.has_key? "accuracy"
      new_hash["accuracy"].to_i > orig_hash["accuracy"].to_i
    end

    # Triggered every time a new element is encountered. We keep state
    # ourselves with the @state variable, turning things on when we
    # get here (and turning things off when we exit in end_element()).
    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block
      @state[:current_tag][name] = true
      case name
      when "status"
        record_host_status(attrs)
      when "address"
        record_address(attrs)
      when "osclass"
        record_host_osclass(attrs)
      when "osmatch"
        record_host_osmatch(attrs)
      when "uptime"
        record_host_uptime(attrs)
      when "hostname"
        record_hostname(attrs)
      when "port"
        record_port(attrs)
      when "state"
        record_port_state(attrs)
      when "service"
        record_port_service(attrs)
      when "script" # Not actually used in import?
        record_port_script(attrs)
        record_host_script(attrs)
        # Ignoring post scripts completely
      when "trace"
        record_host_trace(attrs)
      when "hop"
        record_host_hop(attrs)
      end
    end

    # When we exit a tag, this is triggered.
    def end_element(name=nil)
      block = @block
      case name
      when "os"
        collect_os_data
        @state[:os] = {}
      when "port"
        collect_port_data
        @state[:port] = {}
      when "host" # Roll everything up now
        collect_host_data
        host_object = report_host &block
        if host_object
          db.report_import_note(@args[:wspace],host_object)
          report_services(host_object,&block)
          report_fingerprint(host_object)
          report_uptime(host_object)
          report_traceroute(host_object)
        end
        @state.delete_if {|k| k != :current_tag}
        @report_data = {:wspace => @args[:wspace]}
      end
      @state[:current_tag].delete name
    end

    # We can certainly get fancier with self.send() magic, but
    # leaving this pretty simple for now.

    def record_host_hop(attrs)
      return unless in_tag("host")
      return unless in_tag("trace")
      hops = attr_hash(attrs)
      hops["name"] = hops.delete "host"
      @state[:trace][:hops] << hops
    end

    def record_host_trace(attrs)
      return unless in_tag("host")
      @state[:trace] = attr_hash(attrs)
      @state[:trace][:hops] = []
    end

    def record_host_uptime(attrs)
      return unless in_tag("host")
      @state[:uptime] = attr_hash(attrs)
    end

    def record_host_osmatch(attrs)
      return unless in_tag("host")
      return unless in_tag("os")
      temp_hash = attr_hash(attrs)
      if temp_hash["accuracy"].to_i == 100
        @state[:os] ||= {}
        @state[:os]["osmatch"] = temp_hash["name"]
      end
    end

    def record_host_osclass(attrs)
      return unless in_tag("host")
      return unless in_tag("os")
      @state[:os] ||= {}
      temp_hash = attr_hash(attrs)
      if better_os_match(@state[:os],temp_hash)
        @state[:os] = temp_hash
      end
    end

    def record_hostname(attrs)
      return unless in_tag("host")
      if attr_hash(attrs)["type"] == "PTR"
        @state[:hostname] = attr_hash(attrs)["name"]
      end
    end

    def record_host_script(attrs)
      return unless in_tag("host")
      return if in_tag("port")
      temp_hash = attr_hash(attrs)

      if temp_hash["id"] and temp_hash["output"]
        @state[:scripts] ||= []
        @state[:scripts] << { temp_hash["id"] => temp_hash["output"] }
      end
    end

    def record_port_script(attrs)
      return unless in_tag("host")
      return unless in_tag("port")
      temp_hash = attr_hash(attrs)
      if temp_hash["id"] and temp_hash["output"]
        @state[:port][:scripts] ||= []
        @state[:port][:scripts] << { temp_hash["id"] => temp_hash["output"] }
      end
    end

    def record_port_service(attrs)
      return unless in_tag("host")
      return unless in_tag("port")
      svc = attr_hash(attrs)
      if svc["name"] && @args[:fix_services]
        svc["name"] = db.nmap_msf_service_map(svc["name"])
      end
      @state[:port] = @state[:port].merge(svc)
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
      attrs.each do |k,v|
        next unless k == "state"
        @state[:host_alive] = (v == "up")
      end
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

    def collect_os_data
      return unless in_tag("host")
      if @state[:os]
        @report_data[:os_fingerprint] = {
          :type => "host.os.nmap_fingerprint",
          :data => {
            :os_vendor => @state[:os]["vendor"],
            :os_family => @state[:os]["osfamily"],
            :os_version => @state[:os]["osgen"],
            :os_accuracy => @state[:os]["accuracy"].to_i
          }
        }
        if @state[:os].has_key? "osmatch"
          @report_data[:os_fingerprint][:data][:os_match] = @state[:os]["osmatch"]
        end
      end
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
      if @state[:addresses] and @state[:addresses].has_key?("mac")
        @report_data[:mac] = @state[:addresses]["mac"]
      end
      if @state[:hostname]
        @report_data[:name] = @state[:hostname]
      end
      if @state[:uptime]
        @report_data[:last_boot] = @state[:uptime]["lastboot"]
      end
      if @state[:trace] and @state[:trace].has_key?(:hops)
        @report_data[:traceroute] = @state[:trace]
      end
      if @state[:scripts]
        @report_data[:scripts] = @state[:scripts]
      end
    end

    def collect_port_data
      return unless in_tag("host")
      if @args[:fix_services]
        if @state[:port]["state"] == "filtered"
          return
        end
      end
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
        when "name"
          port_hash[:name] = v
        when "reason"
          port_hash[:reason] = v
        when "product"
          extra[0] = v
        when "version"
          extra[1] = v
        when "extrainfo"
          extra[2] = v
        when :scripts
          port_hash[:scripts] = v
        end
      end
      port_hash[:info] = extra.compact.join(" ") unless extra.empty?
      # Skip localhost port results when they're unknown
      if( port_hash[:reason] == "localhost-response" &&
          port_hash[:state] == Msf::ServiceState::Unknown )
        @report_data[:ports]
      else
        @report_data[:ports] << port_hash
      end
    end

    def report_traceroute(host_object)
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:traceroute]
      tr_note = {
        :workspace => host_object.workspace,
        :host => host_object,
        :type => "host.nmap.traceroute",
        :data => { 'port' => @report_data[:traceroute]["port"].to_i,
          'proto' => @report_data[:traceroute]["proto"].to_s,
          'hops' => @report_data[:traceroute][:hops] }
      }
      db_report(:note, tr_note)
    end

    def report_uptime(host_object)
      return unless host_object.kind_of? ::Mdm::Host
      return unless @report_data[:last_boot]
      up_note = {
        :workspace => host_object.workspace,
        :host => host_object,
        :type => "host.last_boot",
        :data => { :time => @report_data[:last_boot] }
      }
      db_report(:note, up_note)
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
              :type => "nmap.nse.#{k}.host",
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
              :type => "nmap.nse.#{k}." + (svc[:proto] || "tcp") +".#{svc[:port]}",
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

