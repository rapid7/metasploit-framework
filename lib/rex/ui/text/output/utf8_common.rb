# -*- coding: binary -*-

module Rex
module Ui
module Text
class Output::Utf8Common
  def self.with_utf8_encoding(&block)
    external_encoding_on_entry = ::Encoding.default_external
    ::Encoding.default_external = ::Encoding::UTF_8

    internal_encoding_on_entry = ::Encoding.default_internal
    ::Encoding.default_internal = ::Encoding::UTF_8

    begin
      return block.call
    rescue ::StandardError => e
      puts 'Output'
      puts caller
      elog('Failed to call block with UTF8 encoding', error: e)
    ensure
      ::Encoding.default_external = external_encoding_on_entry
      ::Encoding.default_internal = internal_encoding_on_entry
    end
  end
end
end
end
end
