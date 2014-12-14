# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  module Kerberos
    module Microsoft
      module Client

        # @!attribute client
        #   @return [Rex::Proto::Kerberos::Client] The kerberos client
        attr_accessor :client

        def initialize(info = {})
          super

          register_options(
            [
              Opt::RHOST,
              Opt::RPORT(88)
            ], self.class
          )
        end

        # Returns the target host
        #
        # @return [String]
        def rhost
          datastore['RHOST']
        end

        # Returns the remote port
        #
        # @return [String]
        def rport
          datastore['RPORT']
        end

        # Returns the target peer
        #
        # @return [String]
        def peer
          "#{rhost}:#{rport}"
        end

        # Creates a kerberos connection
        #
        # @param opts [Hash{Symbol => <String, Fixnum>}]
        # @option opts [String] :rhost
        # @option opts [<String, Fixnum>] :rport
        # @return [Rex::Proto::Kerberos::Client]
        def connect(opts={})
          kerb_client = Rex::Proto::Kerberos::Client.new(
            hostname: opts[:rhost] || rhost,
            port: (opts[:rport] || rport).to_i,
            context:
              {
                'Msf'        => framework,
                'MsfExploit' => self,
              },
            protocol: 'tcp'
          )

          disconnect if client
          self.client = kerb_client

          kerb_client
        end

        # Disconnects the Kerberos client
        #
        # @param kerb_client [Rex::Proto::Kerberos::Client] the client to disconnect
        def disconnect(kerb_client = client)
          kerb_client.close if kerb_client

          if kerb_client == client
            self.client = nil
          end
        end

        # Performs cleanup as necessary, disconnecting the Kerberos client
        # if it's still established.
        def cleanup
          super
          disconnect
        end

        # Sends a kerberos AS request and reads the response
        # @param opts [Hash]
        # @return [Rex::Proto::Kerberos::Model::Message::KdcResponse]
        def send_request_as(opts = {})
          connect(opts)
          req = build_as_request(opts)
          res = client.send_recv(req)
          disconnect
          res
        end

        def send_request_tgs

        end

        # Builds a kerberos AS request
        #
        # @param opts [Hash]
        # @option opts [Fixnum] :options
        # @option opts [Time] :from
        # @option opts [Time] :till
        # @option opts [Fixnum] :nonce
        # @option opts [Fixnum] :etype
        # @option opts [Array<Rex::Proto::Kerberos::Model::Field::PreAuthData>] :pa_data
        # @option opts [Rex::Proto::Kerberos::Model::Type::PrincipalName] :cname
        # @option opts [String] :realm
        # @option opts [Rex::Proto::Kerberos::Model::Type::PrincipalName] :sname
        # @return [Rex::Proto::Kerberos::Model::Message::KdcRequest]
        def build_as_request(opts = {})
          options = opts[:options] || 0x50800000 # Forwardable, Proxiable, Renewable
          from = opts[:from] || Time.new('1970-01-01-01 00:00:00')
          till = opts[:till] || Time.new('1970-01-01-01 00:00:00')
          rtime = opts[:rtime] || Time.new('1970-01-01-01 00:00:00')
          nonce = opts[:nonce] || Rex::Text.rand_text_numeric(6).to_i
          etype = opts[:etype] || [Rex::Proto::Kerberos::Model::KERB_ETYPE_RC4_HMAC]
          pa_data = opts[:pa_data] || build_as_pa_data(opts)
          cname = build_as_client_name(opts)
          realm = opts[:realm] || ''
          sname = build_as_server_name(opts)

          body = Rex::Proto::Kerberos::Model::Field::KdcRequestBody.new(
            options: options,
            cname: cname,
            realm: realm,
            sname: sname,
            from: from,
            till: till,
            rtime: rtime,
            nonce: nonce,
            etype: etype
          )

          request = Rex::Proto::Kerberos::Model::Message::KdcRequest.new(
            pvno: 5,
            msg_type: Rex::Proto::Kerberos::Model::AS_REQ,
            pa_data: pa_data,
            req_body: body
          )

          request
        end

        def build_tgs_request

        end

        # Builds a kerberos pre authenticated information structure
        #
        # @param opts [Hash]
        # @return [Array<Rex::Proto::Kerberos::Model::Field::PreAuthData>]
        def build_as_pa_data(opts = {})
          pa_data = []

          pa_data << build_as_pa_time_stamp(opts)
          pa_data << build_as_pa_pac_request(opts)

          pa_data
        end

        # Builds a kerberos PA-ENC-TIMESTAMP pre authenticated structure
        #
        # @param opts [Hash{Symbol => <Time, Fixnum, String>}]
        # @option opts [Time] :time_stamp
        # @option opts [Fixnum] :pausec
        # @option opts [Fixnum] :etype
        # @option opts [String] :key
        # @return [Rex::Proto::Kerberos::Model::Field::PreAuthData]
        def build_as_pa_time_stamp(opts = {})
          time_stamp = opts[:time_stamp] || Time.now
          pausec = opts[:pausec] || 0
          etype = opts[:etype] || Rex::Proto::Kerberos::Model::KERB_ETYPE_RC4_HMAC
          key = opts[:key] || ''

          pa_time_stamp = Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp.new(
              pa_time_stamp: time_stamp,
              pausec: pausec
          )

          enc_time_stamp = Rex::Proto::Kerberos::Model::Type::EncryptedData.new(
              etype: etype,
              cipher: pa_time_stamp.encrypt(etype, key)
          )

          pa_enc_time_stamp = Rex::Proto::Kerberos::Model::Field::PreAuthData.new(
              type: Rex::Proto::Kerberos::Model::PA_ENC_TIMESTAMP,
              value: enc_time_stamp.encode
          )

          pa_enc_time_stamp
        end

        # Builds a kerberos PA-PAC-REQUEST pre authenticated structure
        #
        # @param opts [Hash{Symbol => Boolean}]
        # @option opts [Boolean] :pac_request_value
        # @return [Rex::Proto::Kerberos::Model::Field::PreAuthData]
        def build_as_pa_pac_request(opts = {})
          value = opts[:pac_request_value] || false
          pac_request = Rex::Proto::Kerberos::Model::Field::PreAuthPacRequest.new(value: value)
          pa_pac_request = Rex::Proto::Kerberos::Model::Field::PreAuthData.new(
              type: Rex::Proto::Kerberos::Model::PA_PAC_REQUEST,
              value: pac_request.encode
          )

          pa_pac_request
        end

        # Builds a kerberos Client Name Principal
        #
        # @param opts [Hash{Symbol => <String, Fixnum>}]
        # @option opts [String] :cname
        # @option opts [Fixnum] :cname_type
        # @return [Rex::Proto::Kerberos::Model::Type::PrincipalName]
        def build_as_client_name(opts = {})
          name = opts[:cname] || ''
          name_type = opts[:cname_type] || Rex::Proto::Kerberos::Model::NT_PRINCIPAL

          Rex::Proto::Kerberos::Model::Type::PrincipalName.new(
            name_type: name_type,
            name_string: name.split('/')
          )
        end

        # Builds a kerberos Server Name Principal
        #
        # @param opts [Hash{Symbol => <String, Fixnum>}]
        # @option opts [String] :sname the name
        # @option opts [Fixnum] :sname_type the name type
        # @return [Rex::Proto::Kerberos::Model::Type::PrincipalName]
        def build_as_server_name(opts = {})
          name = opts[:sname] || ''
          name_type = opts[:sname_type] || Rex::Proto::Kerberos::Model::NT_PRINCIPAL

          Rex::Proto::Kerberos::Model::Type::PrincipalName.new(
              name_type: name_type,
              name_string: name.split('/')
          )
        end
      end
    end
  end
end
