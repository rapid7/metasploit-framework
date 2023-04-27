# -*- coding: binary -*-

require 'rex/socket'
require 'rex/text'
require 'digest'

module Rex
module Proto
module Http

class HttpSubscriber
  # @param request [Rex::Proto::Http::ClientRequest]
  def on_request(request)
  end

  # @param response [Rex::Proto::Http::Response]
  def on_response(response)
  end
end
end
end
end
