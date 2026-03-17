# -*- coding: binary -*-

module Rex
  module Proto
    module Kerberos
      # Base hook for Kerberos request and response tracing.
      class KerberosSubscriber
        # @param request [Rex::Proto::Kerberos::Model::KdcRequest]
        # @param raw [String,nil]
        # @param context [Hash]
        def on_request(request, raw: nil, context: {}); end

        # @param response [Rex::Proto::Kerberos::Model::KdcResponse, Rex::Proto::Kerberos::Model::KrbError, Rex::Proto::Kerberos::Model::ApRep]
        # @param raw [String,nil]
        # @param context [Hash]
        def on_response(response, raw: nil, context: {}); end
      end
    end
  end
end
