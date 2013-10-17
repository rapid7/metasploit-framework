# -*- coding: binary -*-

require 'msf/core'
require 'rex/text'
require 'rex/exploitation/jsobfu'

module Rex
module Exploitation

#
# Provides javascript functions to determine addon information.
#
# getMsOfficeVersion(): Returns the version for Microsoft Office
#
class JavascriptAddonsDetect < JSObfu

  def initialize(custom_js = '', opts = {})
    @js = custom_js
    @js += ::File.read(::File.join(::File.dirname(__FILE__), "../", "../", "../", "data", "js", "detect", "addons.js"))

    super @js

    return @js
  end

end
end

end
