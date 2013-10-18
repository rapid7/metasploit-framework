# -*- coding: binary -*-

require 'msf/core'

module Rex
module Exploitation

#
# Provides networking functions in JavaScript
#
class JavascriptNetwork

  def self.ajax_download
  	::File.read(::File.join(::File.dirname(__FILE__), "../", "../", "../", "data", "js", "network", "ajax_download.js"))
  end

end
end

end
