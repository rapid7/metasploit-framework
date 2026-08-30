# -*- coding: binary -*-

module Msf
  class Exploit
    class Remote
      module Kerberos
        module Client
          module ApRequest
            # https://datatracker.ietf.org/doc/html/rfc4120#section-5.5.1
            AP_USE_SESSION_KEY = 0x40000000
            AP_MUTUAL_REQUIRED = 0x20000000

            def build_service_ap_request(opts = {})
              authenticator = opts.fetch(:authenticator) do
                build_authenticator(opts.merge(
                  subkey: nil,
                  authenticator_enc_key_usage: Rex::Proto::Kerberos::Crypto::KeyUsage::AP_REQ_AUTHENTICATOR
                ))
              end

              ap_req_options = 0
              ap_req_options |= AP_MUTUAL_REQUIRED if mutual_auth

              ap_req = opts.fetch(:ap_req) do
                build_ap_req(opts.merge(authenticator: authenticator, ap_req_options: ap_req_options))
              end

              ap_req
            end

            def encode_gss_kerberos_ap_request(ap_request_asn1)
              ap_request_mech = wrap_pseudo_asn1(
                  ::Rex::Proto::Gss::OID_KERBEROS_5,
                  TOK_ID_KRB_AP_REQ + ap_request_asn1.to_der
              )
            end

            # @param ap_request_asn1 [Object] The ASN1 KRB_AP_REQ as defined in https://datatracker.ietf.org/doc/html/rfc1964#section-1.1.1
            # @return [String] SPNEGO GSS Blob
            def encode_gss_spnego_ap_request(ap_request_asn1)
              ap_request_mech = encode_gss_kerberos_ap_request(ap_request_asn1)

              OpenSSL::ASN1::ASN1Data.new([
                ::Rex::Proto::Gss::OID_SPNEGO,
                OpenSSL::ASN1::ASN1Data.new([
                  OpenSSL::ASN1::Sequence.new([
                    OpenSSL::ASN1::ASN1Data.new([
                      OpenSSL::ASN1::Sequence.new([
                        ::Rex::Proto::Gss::OID_MICROSOFT_KERBEROS_5
                      ])
                    ], 0, :CONTEXT_SPECIFIC),
                    OpenSSL::ASN1::ASN1Data.new([
                      OpenSSL::ASN1::OctetString.new(ap_request_mech)
                    ], 2, :CONTEXT_SPECIFIC)
                  ])
                ], 0, :CONTEXT_SPECIFIC)
              ], 0, :APPLICATION).to_der
            end
          end
        end
      end
    end
  end
end
