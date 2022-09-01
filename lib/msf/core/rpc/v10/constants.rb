# -*- coding: binary -*-
module Msf
module RPC

API_VERSION = "1.0"


class Exception < RuntimeError
  attr_accessor :code, :message

  # Initializes Exception.
  #
  # @param [Integer] code An error code.
  # @param [String] message An error message.
  # @return [void]
  def initialize(code, message)
    self.code    = code
    self.message = message
  end
end


class ServerException < RuntimeError
  attr_accessor :code, :error_message, :error_class, :error_backtrace

  # Initializes ServerException.
  #
  # @param [Integer] code An error code.
  # @param [String] error_message An error message.
  # @param [Exception] error_class An error class.
  # @param [Array] error_backtrace A backtrace of the error.
  # @return [void]
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
