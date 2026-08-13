# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      # Subscriber interface for observing Kerberos request/response messages.
      class KerberosSubscriber
        # @param request [Rex::Proto::Kerberos::Model::KdcRequest, Rex::Proto::Kerberos::Model::ApReq]
        def on_request(request)
          nil
        end

        # @param response [Rex::Proto::Kerberos::Model::KdcResponse, Rex::Proto::Kerberos::Model::ApRep, Rex::Proto::Kerberos::Model::KrbError]
        def on_response(response)
          nil
        end

        # @param credential [Rex::Proto::Kerberos::CredentialCache::Krb5CcacheCredential]
        # @param source [String,nil]
        def on_credential(credential, source: nil)
          nil
        end

        # @param metadata [Hash] Structured AP-REQ construction trace context.
        def on_ap_req(metadata)
          nil
        end

        # @param metadata [Hash] Structured GSS-Kerberos token wrapping trace context.
        def on_gss_token(metadata)
          nil
        end

        # @param metadata [Hash] Structured SPNEGO token wrapping trace context.
        def on_spnego_token(metadata)
          nil
        end

        # @param metadata [Hash] Structured service-authentication response token trace context.
        def on_response_token(metadata)
          nil
        end

        # @param metadata [Hash] Structured protocol carrier trace context.
        def on_protocol_carrier(metadata)
          nil
        end
      end
    end
  end
end
