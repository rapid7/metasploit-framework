# -*- coding: binary -*-
module Msf
module RPC

class RPC_Base
  attr_accessor :framework, :service, :tokens, :users, :job_status_tracker

  # Initializes framework, service, tokens, and users
  #
  # return [void]
  def initialize(service)
    self.service            = service
    self.framework          = service.framework
    self.tokens             = service.tokens
    self.users              = service.users
    self.job_status_tracker = service.job_status_tracker
  end

  # Raises an Msf::RPC Exception.
  #
  # @param [Integer] code The error code to raise.
  # @param [String] message The error message.
  # @raise [Msf::RPC::Exception]
  # @return [void]
  def error(code, message)
    raise Msf::RPC::Exception.new(code, message)
  end
end

end
end

