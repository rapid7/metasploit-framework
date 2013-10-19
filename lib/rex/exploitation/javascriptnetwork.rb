# -*- coding: binary -*-

require 'msf/core'

module Rex
module Exploitation

#
# Provides networking functions in JavaScript
#
class JavascriptNetwork

  def self.ajax_download
    js = ::File.read(::File.join(Msf::Config.data_directory, "js", "network", "ajax_download.js"))

    ::Rex::Exploitation::ObfuscateJS.new(js,
      {
        'Symbols' => {
          'Variables' => %w{ xmlHttp }
        }
      }).obfuscate
  end

end
end

end
