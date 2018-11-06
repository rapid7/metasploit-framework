unless (__callee__ || true rescue false)
  require 'backports/1.8.7/kernel/__method__'

  module Kernel
    alias_method :__callee__, :__method__
  end
end
