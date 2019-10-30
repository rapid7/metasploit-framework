# -*- coding: binary -*-

require 'msf/base'
require 'msf/base/sessions/scriptable'
require 'rex/post/hwbridge'

module Msf
module Sessions

###
#
# This class provides an interactive session with a hardware bridge.
# The hardware bridge must support the current API supported by Metasploit.
#
###
class HWBridge  < Rex::Post::HWBridge::Client

  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  #
  # This interface supports interactive commands.
  #
  include Msf::Session::Interactive
  include Msf::Session::Scriptable

  #
  # Initialize the HWBridge console
  #
  def initialize(opts={})
    super
    #
    #  The module will manage it's alive state
    #
    self.alive = true

    #
    # Initialize the hwbridge client
    #
    self.init_hwbridge(rstream, opts)

    #
    # Create the console instance
    #
    self.console = Rex::Post::HWBridge::Ui::Console.new(self)
  end

  #
  # Returns the type of session.
  #
  def self.type
    "hwbridge"
  end

  #
  # Returns the session description.
  #
  def desc
    "Hardware bridge interface"
  end

  #
  # We could tie this into payload UUID
  #
  def platform
    "hardware"
  end

  #
  # We could tie this into payload UUID
  #
  def arch
    ARCH_CMD
  end

  #
  # Session info based on the type of hw bridge we are connected to
  # This information comes after connecting to a bridge and pulling status info
  #
  def info
   if exploit
     if exploit.hw_specialty
       info = ""
       exploit.hw_specialty.each_key do |k|
         if exploit.hw_specialty[k] == true
           info += "," if info.length > 0
           info += k
         end
       end
       return info
     end
   end
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Initializes the console's I/O handles.
  #
  def init_ui(input, output)
    self.user_input = input
    self.user_output = output
    console.init_ui(input, output)
    console.set_log_source(log_source)

    super
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Resets the console's I/O handles.
  #
  def reset_ui
    console.unset_log_source
    console.reset_ui
  end


  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Interacts with the hwbridge client at a user interface level.
  #
  def _interact
    framework.events.on_session_interact(self)
    # Call the console interaction subsystem of the meterpreter client and
    # pass it a block that returns whether or not we should still be
    # interacting.  This will allow the shell to abort if interaction is
    # canceled.
    console.interact { self.interacting != true }

    # If the stop flag has been set, then that means the user exited.  Raise
    # the EOFError so we can drop this handle like a bad habit.
    raise EOFError if (console.stopped? == true)
  end

  def alive?
    self.alive
  end

  #
  # Calls the class method.
  #
  def type
    self.class.type
  end

  #
  # Loads the automotive extension
  #
  def load_automotive
    original = console.disable_output
    console.disable_output = true
    console.run_single('load automotive')
    console.disable_output = original
  end

  #
  # Loads the zigbee extension
  #
  def load_zigbee
    original = console.disable_output
    console.disable_output = true
    console.run_single('load zigbee')
    console.disable_output = original
  end

  #
  # Loads the rftransceiver extension
  #
  def load_rftransceiver
    original = console.disable_output
    console.disable_output = true
    console.run_single('load rftransceiver')
    console.disable_output = original
  end

  #
  # Load custom methods provided by the hardware
  #
  def load_custom_methods
    original = console.disable_output
    console.disable_output = true
    console.run_single('load_custom_methods')
    console.disable_output = original
  end

  #
  # The shell will have been initialized by default.
  #
  def shell_init
    return true
  end

  attr_accessor :console # :nodoc:
  attr_accessor :alive # :nodoc:
  attr_accessor :api_version
  attr_accessor :fw_version
  attr_accessor :hw_version
  attr_accessor :device_name
private
  attr_accessor :rstream # :nodoc:

end

end
end
