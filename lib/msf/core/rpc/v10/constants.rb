# -*- coding: binary -*-
module Msf
module RPC

API_VERSION = "1.0"


class Exception < RuntimeError
  attr_accessor :code, :message

  def initialize(code, message)
    self.code    = code
    self.message = message
  end
end


class ServerException < RuntimeError
  attr_accessor :code, :error_message, :error_class, :error_backtrace

  def initialize(code, error_message, error_class, error_backtrace)
    self.code          = code
    self.error_message = error_message
    self.error_class   = error_class
    self.error_backtrace = error_backtrace
  end

  def to_s
    "#{self.error_class} #{self.error_message} #{self.error_backtrace}"
  end
end

end
end
