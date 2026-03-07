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
  end

end
end
end