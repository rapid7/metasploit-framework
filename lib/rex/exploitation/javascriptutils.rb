# -*- coding: binary -*-

require 'msf/core'
require 'rex/text'
require 'rex/exploitation/jsobfu'

module Rex
module Exploitation

#
# Javascript utilities
#
class JavascriptUtils

  def self.base64
    js = ::File.read(::File.join(Msf::Config.install_root, "data", "js", "utils", "base64.js"))

    opts = {
      'Symbols' => {
        'Variables' => %w{ Base64 encoding result _keyStr encoded_data utftext input_idx
          input output chr chr1 chr2 chr3 enc1 enc2 enc3 enc4 },
        'Methods'   => %w{ _utf8_encode _utf8_decode encode decode }
      }
    }

    ::Rex::Exploitation::ObfuscateJS.new(js, opts).to_s
  end

end
end

end
