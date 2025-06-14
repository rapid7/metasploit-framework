# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# This class provides a shell driven interface to the meterpreter client API.
#
###
class Console

  include Rex::Ui::Text::DispatcherShell

  # Dispatchers
  require 'rex/post/meterpreter/ui/console/interactive_channel'
  require 'rex/post/meterpreter/ui/console/command_dispatcher'
  require 'rex/post/meterpreter/ui/console/command_dispatcher/core'

  #
  # Initialize the meterpreter console.
  #
  def initialize(client)
    if (Rex::Compat.is_windows())
      super("meterpreter")
    else
      super("%undmeterpreter%clr", '>', Msf::Config.meterpreter_history, nil, :meterpreter)
    end

    # The meterpreter client context
    self.client = client

    # Queued commands array
    self.commands = []

    # Point the input/output handles elsewhere
    reset_ui

    enstack_dispatcher(Console::CommandDispatcher::Core)

    # Set up logging to whatever logsink 'core' is using
    if ! $dispatcher['meterpreter']
      $dispatcher['meterpreter'] = $dispatcher['core']
    end
  end

  #
  # Called when someone wants to interact with the meterpreter client.  It's
  # assumed that init_ui has been called prior.
  #
  def interact(&block)
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
  def interact_with_channel(channel, raw: false)
    channel.extend(InteractiveChannel) unless (channel.kind_of?(InteractiveChannel) == true)
    channel.on_command_proc = self.on_command_proc if self.on_command_proc
    channel.on_print_proc   = self.on_print_proc if self.on_print_proc
    channel.on_log_proc = method(:log_output) if self.respond_to?(:log_output, true)
    channel.raw = raw

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
  # Runs the specified command wrapper in something to catch meterpreter
  # exceptions.
  #
  def run_command(dispatcher, method, arguments)
    begin
      super
    rescue Exception => e
      is_error_handled = self.client.on_run_command_error_proc && self.client.on_run_command_error_proc.call(e) == :handled
      return if is_error_handled
      case e
      when Rex::TimeoutError, Rex::InvalidDestination
        log_error(e.message)
      when Timeout::Error
        log_error('Operation timed out.')
      when RequestError
        log_error(e.to_s)
      when ::Errno::EPIPE, ::OpenSSL::SSL::SSLError, ::IOError
        self.client.kill
      when ::Exception
        log_error("Error running command #{method}: #{e.class} #{e}")
        elog(e)
      end
    end
  end

  #
  # Logs that an error occurred and persists the callstack.
  #
  def log_error(msg)
    print_error(msg)

    elog(msg, 'meterpreter')

    dlog("Call stack:\n#{$@.join("\n")}", 'meterpreter')
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

