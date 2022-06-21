# -*- coding: binary -*-

require 'rex/socket'
require 'rex/text'
require 'digest'

module Rex
module Proto
module Http

class HttpSubscriber
  def on_request(request)
  end

  def on_response(response)
  end
end
end
end
end
