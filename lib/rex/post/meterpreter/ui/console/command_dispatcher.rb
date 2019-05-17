# -*- coding: binary -*-
require 'rex/logging'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Base class for all command dispatchers within the meterpreter console user
# interface.
#
###
module Console::CommandDispatcher

  include Rex::Ui::Text::DispatcherShell::CommandDispatcher

  #
  # The hash of file names to class names after a module has already been
  # loaded once on the client side.
  #
  @@file_hash = {}

  #
  # Checks the file name to hash association to see if the module being
  # requested has already been loaded once.
  #
  def self.check_hash(name)
    @@file_hash[name]
  end

  #
  # Sets the file path to class name association for future reference.
  #
  def self.set_hash(name, klass)
    @@file_hash[name] = klass
  end

  def initialize(shell)
    @msf_loaded = nil
    super
  end

  #
  # Returns the meterpreter client context.
  #
  def client
    shell.client
  end

  #
  # Returns the commands that meet the requirements
  #
  def filter_commands(all, reqs)
    all.delete_if do |cmd, _desc|
      reqs[cmd].any? { |req| !client.commands.include?(req) }
    end
  end

  #
  # Return the subdir of the `documentation/` directory that should be used
  # to find usage documentation
  #
  def docs_dir
    File.join(super, 'meterpreter')
  end

  #
  # Returns true if the client has a framework object.
  #
  # Used for firing framework session events
  #
  def msf_loaded?
    return @msf_loaded unless @msf_loaded.nil?
    # if we get here we must not have initialized yet

    if client.framework
      # We have a framework instance so the msf libraries should be
      # available.  Load up the ones we're going to use
      require 'msf/base/serializer/readable_text'
    end
    @msf_loaded = !!(client.framework)
    @msf_loaded
  end

  #
  # Log that an error occurred.
  #
  def log_error(msg)
    print_error(msg)

    elog(msg, 'meterpreter')

    dlog("Call stack:\n#{$@.join("\n")}", 'meterpreter')
  end

end

end
end
end
end
