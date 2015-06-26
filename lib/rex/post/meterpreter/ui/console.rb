# -*- coding: binary -*-
require 'rex/ui'
require 'rex/post/meeterpeter'
require 'rex/logging'

module Rex
module Post
module meeterpeter
module Ui

###
#
# This class provides a shell driven interface to the meeterpeter client API.
#
###
class Console

  include Rex::Ui::Text::DispatcherShell

  # Dispatchers
  require 'rex/post/meeterpeter/ui/console/interactive_channel'
  require 'rex/post/meeterpeter/ui/console/command_dispatcher'
  require 'rex/post/meeterpeter/ui/console/command_dispatcher/core'

  #
  # Initialize the meeterpeter console.
  #
  def initialize(client)
    if (Rex::Compat.is_windows())
      super("meeterpeter")
    else
      super("%undmeeterpeter%clr")
    end

    # The meeterpeter client context
    self.client = client

    # Queued commands array
    self.commands = []

    # Point the input/output handles elsewhere
    reset_ui

    enstack_dispatcher(Console::CommandDispatcher::Core)

    # Set up logging to whatever logsink 'core' is using
    if ! $dispatcher['meeterpeter']
      $dispatcher['meeterpeter'] = $dispatcher['core']
    end
  end

  #
  # Called when someone wants to interact with the meeterpeter client.  It's
  # assumed that init_ui has been called prior.
  #
  def interact(&block)
    init_tab_complete

    # Run queued commands
    commands.delete_if { |ent|
      run_single(ent)
      true
    }

    # Run the interactive loop
    run { |line|
      # Run the command
      run_single(line)

      # If a block was supplied, call it, otherwise return false
      if (block)
        block.call
      else
        false
      end
    }
  end

  #
  # Interacts with the supplied channel.
  #
  def interact_with_channel(channel)
    channel.extend(InteractiveChannel) unless (channel.kind_of?(InteractiveChannel) == true)
    channel.on_command_proc = self.on_command_proc if self.on_command_proc
    channel.on_print_proc   = self.on_print_proc if self.on_print_proc

    channel.interact(input, output)
    channel.reset_ui
  end

  #
  # Queues a command to be run when the interactive loop is entered.
  #
  def queue_cmd(cmd)
    self.commands << cmd
  end

  #
  # Runs the specified command wrapper in something to catch meeterpeter
  # exceptions.
  #
  def run_command(dispatcher, method, arguments)
    begin
      super
    rescue Timeout::Error
      log_error("Operation timed out.")
    rescue RequestError => info
      log_error(info.to_s)
    rescue Rex::InvalidDestination => e
      log_error(e.message)
    rescue ::Errno::EPIPE, ::OpenSSL::SSL::SSLError, ::IOError
      self.client.kill
    rescue  ::Exception => e
      log_error("Error running command #{method}: #{e.class} #{e}")
    end
  end

  #
  # Logs that an error occurred and persists the callstack.
  #
  def log_error(msg)
    print_error(msg)

    elog(msg, 'meeterpeter')

    dlog("Call stack:\n#{$@.join("\n")}", 'meeterpeter')
  end

  attr_reader :client # :nodoc:

protected

  attr_writer :client # :nodoc:
  attr_accessor :commands # :nodoc:

end

end
end
end
end

