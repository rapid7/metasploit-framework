# -*- coding: binary -*-
require 'rex/proto/kerberos'

module Msf
  module Kerberos
    module Microsoft
      module Client
        module TgsRequest
          def build_tgs_request(opts = {})
            options = opts[:options] || 0x50800000 # Forwardable, Proxiable, Renewable
            from = opts[:from] || Time.new('1970-01-01-01 00:00:00')
            till = opts[:till] || Time.new('1970-01-01-01 00:00:00')
            rtime = opts[:rtime] || Time.new('1970-01-01-01 00:00:00')
            nonce = opts[:nonce] || Rex::Text.rand_text_numeric(6).to_i
            etype = opts[:etype] || [Rex::Proto::Kerberos::Model::KERB_ETYPE_RC4_HMAC]
            cname = build_client_name(opts)
            realm = opts[:realm] || ''
            sname = build_server_name(opts)

            pac = build_pac(opts)

            opts.merge({:pac => pac})

            build_authorization_data(opts)

            body = Rex::Proto::Kerberos::Model::KdcRequestBody.new(
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

            pa_data = opts[:pa_data] || build_tgs_pa_data(opts)

            request = Rex::Proto::Kerberos::Model::KdcRequest.new(
              pvno: 5,
              msg_type: Rex::Proto::Kerberos::Model::TGS_REQ,
              pa_data: pa_data,
              req_body: body
            )

            request
          end

          def build_authorization_data(opts)
=begin
        ad1 = AuthorizationData()
        ad1[0] = None
        ad1[0]['ad-type'] = authorization_data[0]
        ad1[0]['ad-data'] = authorization_data[1]
        ad = AuthorizationData()
        ad[0] = None
        ad[0]['ad-type'] = AD_IF_RELEVANT
        ad[0]['ad-data'] = encode(ad1)
        enc_ad = (subkey[0], encrypt(subkey[0], subkey[1], 5, encode(ad)))
=end
          end

          def build_pac(opts)
            user_name = opts[:cname] || ''
            user_id = opts[:user_id] || 1000
            primary_group_id = opts[:group_id] || 513
            group_ids = opts[:group_ids] || [513]
            domain_name = opts[:realm] || ''
            domain_id = opts[:doman_id] || ''
            logon_time = opts[:logon_time] || Time.now
            checksum_type = opts[:checksum_type] || Rex::Proto::Kerberos::Crypto::RsaMd5::RSA_MD5

            logon_info = Rex::Proto::Kerberos::Pac::LogonInfo.new(
              logon_time: logon_time,
              effective_name: user_name,
              user_id: user_id,
              primary_group_id: primary_group_id,
              group_ids: group_ids,
              logon_domain_name: domain_name,
              logon_domain_id: domain_id,
            )

            client_info = Rex::Proto::Kerberos::Pac::ClientInfo.new(
              client_id: logon_time,
              name: user_name
            )

            server_checksum = Rex::Proto::Kerberos::Pac::ServerChecksum.new(
              checksum: checksum_type
            )

            priv_srv_checksum = Rex::Proto::Kerberos::Pac::PrivSvrChecksum.new(
              checksum: checksum_type
            )

            pac_type = Rex::Proto::Kerberos::Pac::Type.new(
              buffers: [
                logon_info,
                client_info,
                server_checksum,
                priv_srv_checksum
              ],
              checksum: checksum_type
            )

            pac_type
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

          # Builds a kerberos AP-REQ inside a pre authenticated structure
          #
          # @param opts[Hash]
          # @option opts [Fixnum] :pvno
          # @option opts [Fixnum] :msg_type
          # @option opts [Fixnum] :ap_req_options
          # @option opts [Rex::Proto::Kerberos::Model::Ticket] :ticket
          # @option opts [Rex::Proto::Kerberos::Model::Authenticator] :authenticator
          # @return [Rex::Proto::Kerberos::Model::PreAuthData]
          #authenticator = build_authenticator(user_realm, user_name, chksum, subkey, current_time)#, ad)

          def build_pa_tgs_req(opts = {})
            pvno = opts[:pvno] || Rex::Proto::Kerberos::Model::VERSION
            msg_type = opts[:msg_type] || Rex::Proto::Kerberos::Model::AP_REQ
            options = opts[:ap_req_options] || 0
            ticket = opts[:ticket]
            authenticator = opts[:authenticator] || build_authenticator(opts)

            if ticket.nil?
              raise ::RuntimeError, 'Building a AP-REQ without ticket not supported'
            end

            if authenticator.nil?
              raise ::RuntimeError, 'Building an AP-REQ without authenticator not supporeted'
            end

            ap_req = Rex::Proto::Kerberos::Model::ApReq.new(
              pvno: pvno,
              msg_type: msg_type,
              options: options,
              ticket: ticket,
              authenticator: authenticator
            )

            pa_tgs_req = Rex::Proto::Kerberos::Model::PreAuthData.new(
              type: Rex::Proto::Kerberos::Model::PA_TGS_REQ,
              value: ap_req.encode
            )

            pa_tgs_req
          end

          def build_authenticator(opts = {})
            cname = build_client_name(opts)
            realm = opts[:realm] || ''
            ctime = opts[:ctime] || Time.now
            cusec = opts[:cusec] || ctime.usec

            Rex::Proto::Kerberos::Model::Authenticator.new(
              vno: 5,
              crealm: realm,
              cname: cname,
              checksum: checksum,
              cusec: cusec,
              ctime: ctime,
              subkey: enc_key
            )
          end
        end
      end
    end
  end
end
