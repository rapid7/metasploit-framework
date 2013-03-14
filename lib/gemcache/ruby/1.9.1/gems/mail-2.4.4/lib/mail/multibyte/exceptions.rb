# encoding: utf-8

module Mail #:nodoc:
  module Multibyte #:nodoc:
    # Raised when a problem with the encoding was found.
    class EncodingError < StandardError; end
  end
end