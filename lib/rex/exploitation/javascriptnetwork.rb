# -*- coding: binary -*-

require 'msf/core'
require 'rex/text'
require 'rex/exploitation/jsobfu'

module Rex
module Exploitation

#
# Provides networking functions in JavaScript
#
class JavascriptNetwork < JSObfu

  def self.ajax_download
  	::File.read(::File.join(::File.dirname(__FILE__), "../", "../", "../", "data", "js", "network", "ajax_download.js"))
  end

end
end

end
