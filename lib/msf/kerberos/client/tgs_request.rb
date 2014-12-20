# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  module Kerberos
    module Client
      module TgsRequest

        def build_tgs_request(opts = {})
          subkey = build_subkey(opts)

          opts.merge!({:subkey => subkey})

          if opts[:auth_data] && !opts[:enc_auth_data]
            enc_auth_data = build_enc_auth_data(opts)
            opts.merge!({:enc_auth_data => enc_auth_data})
          end

          body = build_tgs_request_body(opts)

          checksum_body = body.checksum(7)
          checksum = Rex::Proto::Kerberos::Model::Checksum.new(
            type: 7,
            checksum: checksum_body
          )
          opts.merge!({:checksum => checksum})

          # Finally authenticator and pa_data

          authenticator = build_authenticator(opts)

          opts.merge!({:authenticator => authenticator})

          #pa_data = opts[:pa_data] || build_tgs_pa_data(opts)
          pa_data = []
          pa_data.push(build_pa_tgs_req(opts))
          if opts[:pa_data]
            opts[:pa_data].each { |pa| pa_data.push(pa) }
          end

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

        def build_subkey(opts={})
          subkey_type = opts[:subkey_type] || 23
          subkey_value = opts[:subkey_value] || Rex::Text.rand_text(16)

          subkey = Rex::Proto::Kerberos::Model::EncryptionKey.new(
              type: subkey_type,
              #value: Rex::Text.rand_text(16)
              value: "AAAABBBBCCCCDDDD"
          )

          subkey
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

        def build_tgs_request_body(opts = {})
          options = opts[:options] || 0x50800000 # Forwardable, Proxiable, Renewable
          from = opts[:from] || Time.utc('1970-01-01-01 00:00:00')
          till = opts[:till] || Time.utc('1970-01-01-01 00:00:00')
          rtime = opts[:rtime] || Time.utc('1970-01-01-01 00:00:00')
          nonce = opts[:nonce] || Rex::Text.rand_text_numeric(6).to_i
          etype = opts[:etype] || [Rex::Proto::Kerberos::Model::KERB_ETYPE_RC4_HMAC]
          cname = opts[:cname] || build_client_name(opts)
          realm = opts[:realm] || ''
          sname = opts[:sname] || build_server_name(opts)
          enc_auth_data = opts[:enc_auth_data] || nil


          Rex::Proto::Kerberos::Model::KdcRequestBody.new(
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
        end
      end
    end
  end
end
