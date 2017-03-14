# -*- coding: binary -*-
require "rex/parser/nokogiri_doc_mixin"
require 'uri'

module Rex
  module Parser

    # If Nokogiri is available, define Burp Issue document class.
    load_nokogiri && class BurpIssueDocument < Nokogiri::XML::SAX::Document

      include NokogiriDocMixin

      def start_element(name=nil,attrs=[])
        attrs = normalize_attrs(attrs)
        block = @block
        @state[:current_tag][name] = true
        case name
          when "host", "name", "info", "issueDetail", "references"
            @state[:has_text] = true
        end
      end

      def end_element(name=nil)
        block = @block
        case name
          when "issue"
            report_web_host_info
            report_web_service_info
            report_vuln
            # Reset the state once we close a host
            @state = @state.select {|k| [:current_tag].include? k}
          when "host"
            @state[:has_text] = false
            collect_host_info
            @text = nil
          when "name"
            @state[:has_text] = false
            collect_name
            @text = nil
          when "issueDetail"
            @state[:has_text] = false
            collect_issue_detail
            @text = nil
          when "references"
            @state[:has_text] = false
            collect_references
            @text = nil
        end
        @state[:current_tag].delete name
      end

      def collect_host_info
        return unless in_issue
        return unless has_text
        uri = URI(@text)

        @state[:host] = uri.host
        @state[:service_name] = uri.scheme
        @state[:proto] = "tcp"

        case @state[:service_name]
          when "http"
            @state[:port] = 80
          when "https"
            @state[:port] = 443
        end
      end

      def collect_name
        return unless in_issue
        return unless has_text
        @state[:vuln_name] = @text
      end

      def collect_issue_detail
        return unless in_issue
        return unless has_text
        @state[:issue_detail] = @text
      end

      def collect_references
        return unless in_issue
        return unless has_text
        uri = @text.match('href=[\'"]?([^\'" >]+)')[1]
        @state[:refs] = ["URI-#{uri}"]
      end

      def report_web_host_info
        return unless @state[:host]
        address = Rex::Socket.resolv_to_dotted(@state[:host]) rescue nil
        host_info = {workspace: @args[:wspace]}
        host_info[:address] = address
        host_info[:name] = @state[:host]
        db_report(:host, host_info)
      end

      def report_web_service_info
        return unless @state[:host]
        return unless @state[:port]
        return unless @state[:proto]
        return unless @state[:service_name]
        service_info = {workspace: @args[:wspace]}
        service_info[:host] = @state[:host]
        service_info[:port] = @state[:port]
        service_info[:proto] = @state[:proto]
        service_info[:name] = @state[:service_name]
        @state[:service_object] = db_report(:service, service_info)
      end

      def report_vuln
        return unless @state[:service_object]
        return unless @state[:vuln_name]
        return unless @state[:issue_detail]
        vuln_info = {workspace: @args[:wspace]}
        vuln_info[:service_id] = @state[:service_object].id
        vuln_info[:host] = @state[:host]
        vuln_info[:name] = @state[:vuln_name]
        vuln_info[:info] = @state[:issue_detail]
        vuln_info[:refs] = @state[:refs]
        @state[:vuln_object] = db_report(:vuln, vuln_info)
      end

      def in_issue
        return false unless in_tag("issue")
        return false unless in_tag("issues")
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

