# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"

require 'msf/core'

module Rex
  module Parser

    # If Nokogiri is available, define the document class.
    load_nokogiri && class CIDocument < Nokogiri::XML::SAX::Document

    include NokogiriDocMixin

    attr_reader :text

    def initialize(*args)
      super(*args)
      @state[:has_text] = true
    end

    # Triggered every time a new element is encountered. We keep state
    # ourselves with the @state variable, turning things on when we
    # get here (and turning things off when we exit in end_element()).
    def start_element(name=nil,attrs=[])
      attrs = normalize_attrs(attrs)
      block = @block

      r = { :e => name }
      attrs.each { |pair| r[pair[0]] = pair[1] }

      if @state[:path]
        @state[:path].push r
      end

      case name
      when "entity"
        @state[:path] = [ r ]
        record_device(r)
      when "property"
        return if not @state[:address]
        return if not @state[:props]
        @state[:props] << [ r["type"], r["key"]]
      end
    end

    # When we exit a tag, this is triggered.
    def end_element(name=nil)
      block = @block
      case name
      when "entity" # Wrap it up
        if @state[:address]
          host_object = report_host &block
          report_services(host_object)
          report_vulns(host_object)
        end
        # Reset the state once we close a host
        @report_data = {:wspace => @args[:wspace]}
        @state[:root] = {}
      when "property"
        if @state[:props]
          @text.strip! if @text
          process_property
          @state[:props].pop
        end
      end
      @state[:path].pop
      @text = nil
    end

    def record_device(info)
      if info["class"] and info["class"] == "host" and info["name"]
        address = info["name"].to_s.gsub(/^.*\//, '')
        return if address !~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/
        @state[:address] = address
        @state[:props]   = []
      end
    end

    def process_property
      return if not @state[:props]
      return if not @state[:props].length > 0
      @state[:root] ||= {}
      @cobj = @state[:root]
      property_parser(0)
    end

    def property_parser(idx)
      return if not @state[:props][idx]
      case @state[:props][idx][0]
      when "container", "ports", "entity", "properties"
        @cobj[ @state[:props][idx][1] ] ||= {}
        @cobj = @cobj[ @state[:props][idx][1] ]
      else
        @cobj[ state[:props][idx][1] ] = @text
      end
      property_parser(idx + 1)
    end

    def report_host(&block)
      @report_data = {
        :ports  => [:ignore],
        :state  => Msf::HostState::Alive,
        :host   => @state[:address]
      }

      if @state[:root]["dns names"] and @state[:root]["dns names"].keys.length > 0
        @report_data[:name] = @state[:root]["dns names"].keys.first
      end

      if host_is_okay
        @report_data.delete(:ports)

        db.emit(:address, @report_data[:host],&block) if block
        host_object = db_report(:host, @report_data.merge(
          :workspace => @args[:wspace] ) )
        if host_object
          db.report_import_note(host_object.workspace, host_object)
        end
        host_object
      end
    end

    def report_services(host_object)
      return unless host_object.kind_of? ::Mdm::Host

      snames = {}
      ( @state[:root]["services"] || {} ).each_pair do |sname, sinfo|
        sinfo.each_pair do |pinfo,pdata|
          snames[pinfo] = sname.dup
        end
      end

      reported = []
      if @state[:root]["tcp_ports"]
        @state[:root]["tcp_ports"].each_pair do |pn, ps|
          ps = "open" if ps == "listen"
          svc = { :port => pn.to_i, :state => ps, :proto => 'tcp'}
          if @state[:root]["Banners"] and @state[:root]["Banners"][pn.to_s]
            svc[:info] = @state[:root]["Banners"][pn.to_s]
          end
          svc[:name] = snames["#{pn}-tcp"] if snames["#{pn}-tcp"]
          reported << db_report(:service, svc.merge(:host => host_object))
        end
      end

      if @state[:root]["udp_ports"]
        @state[:root]["udp_ports"].each_pair do |pn, ps|
          ps = "open" if ps == "listen"
          svc = { :port => pn.to_i, :state => ps, :proto => 'udp'}
          svc[:name] = snames["#{pn}-udp"] if snames["#{pn}-tcp"]
          reported << db_report(:service, svc.merge(:host => host_object))
        end
      end

      ( @state[:root]["services"] || {} ).each_pair do |sname, sinfo|
        sinfo.each_pair do |pinfo,pdata|
          sport,sproto = pinfo.split("-")
          db_report(:note, {
            :host => host_object,
            :port => sport.to_i,
            :proto => sproto,
            :ntype => "ci.#{sname}.fingerprint",
            :data => pdata
          })
        end
      end

      reported
    end

    def report_vulns(host_object)
      vuln_count = 0
      block = @block
      return unless host_object.kind_of? ::Mdm::Host
      return unless @state[:root]["Vulnerabilities"]
      @state[:root]["Vulnerabilities"].each_pair do |cve, vinfo|
        vinfo.each_pair do |vname, vdesc|
          data = {
            :workspace => host_object.workspace,
            :host => host_object,
            :name => vname,
            :info => vdesc,
            :refs => [ cve ]
          }
          db_report(:vuln, data)
        end
      end
    end

  end
end
end

