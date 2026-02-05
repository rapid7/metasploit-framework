# -*- coding: binary -*-
module Msf
module RPC

API_VERSION = "1.0"


class Exception < RuntimeError
  attr_accessor :code, :message, :http_msg

  # Initializes Exception.
  #
  # @param [Integer] code An error code.
  # @param [String] message An error message.
  # @return [void]
  def initialize(code, message, http_msg = nil)
    self.code    = code
    self.message = message
    self.http_msg = http_msg
    self.http_msg ||= case self.code
                      when 400
                        'Bad Request'
                      when 401
                        'Unauthorized'
                      when 403
                        'Forbidden'
                      when 404
                        'Not Found'
                      when 500
                        'Internal Server Error'
                      else
                        'Unknown Error'
                      end
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
