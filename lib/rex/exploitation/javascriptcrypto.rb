# -*- coding: binary -*-

require 'msf/core'
require 'rex/text'
require 'rex/exploitation/jsobfu'

module Rex
module Exploitation

#
# Provides cryptographic functions in JavaScript
#
class JavascriptCrypto < JSObfu

  def self.base64
  	::File.read(::File.join(::File.dirname(__FILE__), "../", "../", "../", "data", "js", "crypto", "base64.js"))
  end

end
end

end
