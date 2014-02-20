# -*- coding: binary -*-

require 'msf/core'

module Rex
module Exploitation
module Js

#
# Provides meomry manipulative functions in JavaScript
#
class Memory

  def self.mstime_malloc
    js = ::File.read(::File.join(Msf::Config.data_directory, "js", "memory", "mstime_malloc.js"))
    js = js.gsub(/W00TA/, Rex::Text.rand_text_hex(6))
    js = js.gsub(/W00TB/, Rex::Text.rand_text_hex(5))

    ::Rex::Exploitation::ObfuscateJS.new(js,
      {
        'Symbols' => {
          'Variables' => %w{ buf eleId acTag }
        }
      }).obfuscate
  end

  def self.property_spray
    js = ::File.read(::File.join(Msf::Config.data_directory, "js", "memory", "property_spray.js"))

    ::Rex::Exploitation::ObfuscateJS.new(js,
      {
        'Symbols' => {
          'Variables' => %w{ sym_div_container data junk obj }
        }
      }).obfuscate
  end

  def self.heap_spray
    js = ::File.read(::File.join(Msf::Config.data_directory, "js", "memory", "heap_spray.js"))

    ::Rex::Exploitation::ObfuscateJS.new(js,
      {
        'Symbols' => {
          'Variables' => %w{ index heapSprayAddr_hi heapSprayAddr_lo retSlide heapBlockCnt }
        }
      }).obfuscate
  end

end
end
end
end
