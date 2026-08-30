# -*- coding: binary -*-
module Msf
module RPC
class RPC_Health < RPC_Base

  # Returns whether the service is currently healthy and ready to accept
  # requests. This endpoint is not authenticated.
  #
  # @return [Hash]
  # @example Here's how you would use this from the client:
  #  rpc.call('health.check')
  def rpc_check_noauth
    Msf::RPC::Health.check(framework)
  end

end
end
end
