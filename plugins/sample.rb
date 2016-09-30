#
# $Id$
#

module Msf

###
#
# This class illustrates a sample plugin.  Plugins can change the behavior of
# the framework by adding new features, new user interface commands, or
# through any other arbitrary means.  They are designed to have a very loose
# definition in order to make them as useful as possible.
#
# $Revision$
###
class Plugin::Sample < Msf::Plugin

  ###
  #
  # This class implements a sample console command dispatcher.
  #
  ###
  class ConsoleCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    #
    # The dispatcher's name.
    #
    def name
      "Sample"
    end

    #
    # Returns the hash of commands supported by this dispatcher.
    #
    def commands
      {
        "sample" => "A sample command added by the sample plugin"
      }
    end

    #
    # This method handles the sample command.
    #
    def cmd_sample(*args)
      print_line("You passed: #{args.join(' ')}")
    end
  end

  #
  # The constructor is called when an instance of the plugin is created.  The
  # framework instance that the plugin is being associated with is passed in
  # the framework parameter.  Plugins should call the parent constructor when
  # inheriting from Msf::Plugin to ensure that the framework attribute on
  # their instance gets set.
  #
  def initialize(framework, opts)
    super

    # If this plugin is being loaded in the context of a console application
    # that uses the framework's console user interface driver, register
    # console dispatcher commands.
    add_console_dispatcher(ConsoleCommandDispatcher)

    print_status("Sample plugin loaded.")
  end

  #
  # The cleanup routine for plugins gives them a chance to undo any actions
  # they may have done to the framework.  For instance, if a console
  # dispatcher was added, then it should be removed in the cleanup routine.
  #
  def cleanup
    # If we had previously registered a console dispatcher with the console,
    # deregister it now.
    remove_console_dispatcher('Sample')
  end

  #
  # This method returns a short, friendly name for the plugin.
  #
  def name
    "sample"
  end

  #
  # This method returns a brief description of the plugin.  It should be no
  # more than 60 characters, but there are no hard limits.
  #
  def desc
    "Demonstrates using framework plugins"
  end

protected
end

end
