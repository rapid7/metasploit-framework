# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  module Kerberos
    module Client
      module TgsRequest
        def build_tgs_request(opts = {})
          options = opts[:options] || 0x50800000 # Forwardable, Proxiable, Renewable
          from = opts[:from] || Time.utc('1970-01-01-01 00:00:00')
          till = opts[:till] || Time.utc('1970-01-01-01 00:00:00')
          rtime = opts[:rtime] || Time.utc('1970-01-01-01 00:00:00')
          nonce = opts[:nonce] || Rex::Text.rand_text_numeric(6).to_i
          etype = opts[:etype] || [Rex::Proto::Kerberos::Model::KERB_ETYPE_RC4_HMAC]
          cname = opts[:cname] || build_client_name(opts)
          realm = opts[:realm] || ''
          sname = opts[:sname] || build_server_name(opts)

          subkey = Rex::Proto::Kerberos::Model::EncryptionKey.new(
            type: 23,
            #value: Rex::Text.rand_text(16)
            value: "AAAABBBBCCCCDDDD"
          )

          opts.merge!({:subkey => subkey})

          if opts[:auth_data]
            enc_auth_data = build_enc_auth_data(opts)
          end

          body = Rex::Proto::Kerberos::Model::KdcRequestBody.new(
            options: options,
            cname: cname,
            realm: realm,
            sname: sname,
            from: from,
            till: till,
            rtime: rtime,
            nonce: nonce,
            etype: etype,
            enc_auth_data: enc_auth_data
          )

          checksum_body = body.checksum(7)
          checksum = Rex::Proto::Kerberos::Model::Checksum.new(
            type: 7,
            checksum: checksum_body
          )
          opts.merge!({:checksum => checksum})

          # Finally authenticator and pa_data

          authenticator = build_authenticator(opts)

          opts.merge!({:authenticator => authenticator})

          pa_data = opts[:pa_data] || build_tgs_pa_data(opts)

          request = Rex::Proto::Kerberos::Model::KdcRequest.new(
            pvno: 5,
            msg_type: Rex::Proto::Kerberos::Model::TGS_REQ,
            pa_data: pa_data,
            req_body: body
          )

          request
        end

        def build_enc_auth_data(opts)
          auth_data = opts[:auth_data]
          key = opts[:subkey].value #|| ''
          etype = opts[:subkey].type #|| Rex::Proto::Kerberos::Model::KERB_ETYPE_RC4_HMAC

          encrypted = auth_data.encrypt(etype, key)

          e_data = Rex::Proto::Kerberos::Model::EncryptedData.new(
            etype: etype,
            cipher: encrypted
          )

          e_data
        end

        # Builds a kerberos pre authenticated information structure for an TGS request
        #
        # @param opts [Hash]
        # @return [Array<Rex::Proto::Kerberos::Model::PreAuthData>]
        def build_tgs_pa_data(opts = {})
          pa_data = []

          pa_data << build_pa_tgs_req(opts)
          pa_data << build_pa_pac_request(opts)

          pa_data
        end

        def build_pa_tgs_req(opts = {})
          pvno = opts[:pvno] || Rex::Proto::Kerberos::Model::VERSION
          msg_type = opts[:msg_type] || Rex::Proto::Kerberos::Model::AP_REQ
          options = opts[:ap_req_options] || 0
          ticket = opts[:ticket]
          authenticator = opts[:authenticator]
          session_key = opts[:session_key]

          if ticket.nil?
            raise ::RuntimeError, 'Building a AP-REQ without ticket not supported'
          end

          if authenticator.nil?
            raise ::RuntimeError, 'Building an AP-REQ without authenticator not supporeted'
          end

          enc_authenticator = Rex::Proto::Kerberos::Model::EncryptedData.new(
            etype: session_key.type,
            cipher: authenticator.encrypt(session_key.type, session_key.value)
          )

          ap_req = Rex::Proto::Kerberos::Model::ApReq.new(
            pvno: pvno,
            msg_type: msg_type,
            options: options,
            ticket: ticket,
            authenticator: enc_authenticator
          )

          pa_tgs_req = Rex::Proto::Kerberos::Model::PreAuthData.new(
            type: Rex::Proto::Kerberos::Model::PA_TGS_REQ,
            value: ap_req.encode
          )

          pa_tgs_req
        end

        def build_authenticator(opts = {})
          cname = opts[:cname] || build_client_name(opts)
          realm = opts[:realm] || ''
          ctime = opts[:ctime] || Time.now
          cusec = opts[:cusec] || ctime.usec
          checksum = opts[:checksum] || ''
          subkey = opts[:subkey]

          Rex::Proto::Kerberos::Model::Authenticator.new(
            vno: 5,
            crealm: realm,
            cname: cname,
            checksum: checksum,
            cusec: cusec,
            ctime: ctime,
            subkey: subkey
          )
        end
      end
    end
  end
end
