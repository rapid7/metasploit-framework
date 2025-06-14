# -*- coding: binary -*-

module Rex
module Post
module HWBridge
module Ui

###
#
# Base class for all command dispatchers within the hwbridge console user
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
  # Returns the hwbridge client context.
  #
  def client
    shell.client
  end

  #
  # Returns true if the client has a framework object.
  #
  # Used for firing framework session events
  #
  def msf_loaded?
    return @msf_loaded unless @msf_loaded.nil?
    # if we get here we must not have initialized yet

    @msf_loaded = !!(client.framework)
    @msf_loaded
  end

  #
  # Log that an error occurred.
  #
  def log_error(msg)
    print_error(msg)

    elog(msg, 'hwbridge', error: $!)
  end

end

end
end
end
end
