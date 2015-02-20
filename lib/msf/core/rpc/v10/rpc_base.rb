# -*- coding: binary -*-
module Msf
module RPC

class RPC_Base
  attr_accessor :framework, :service, :tokens, :users

  def initialize(service)
    self.service   = service
    self.framework = service.framework
    self.tokens    = service.tokens
    self.users     = service.users
  end

  def error(code, message)
    raise Msf::RPC::Exception.new(code, message)
  end
end

end
end

