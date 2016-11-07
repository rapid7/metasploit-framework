require 'rex/ui'
require 'rex/logging'

module Msf
module Sessions
class SSH
module Ui

class Console
  autoload :CommandDispatcher, 'msf/base/sessions/ssh/ui/console/command_dispatcher'

  include Rex::Ui::Text::DispatcherShell

  # @param client [Msf::Session::SSH]
  def initialize(client)
    prompt = "metaSSH"
    super(prompt)
    # The meterpreter client context
    self.client = client

    # Point the input/output handles elsewhere
    reset_ui

    enstack_dispatcher(CommandDispatcher)

    # Set up logging to whatever logsink 'core' is using
    if ! $dispatcher['ssh']
      $dispatcher['ssh'] = $dispatcher['core']
    end
  end

  #
  # Called when someone wants to interact with the ssh client.  It's
  # assumed that init_ui has been called prior.
  #
  def interact(&block)
    init_tab_complete

    # Run the interactive loop
    run do |line|
      run_single(line)

      if (block)
        block.call
      else
        false
      end
    end
  end

  #
  # Logs that an error occurred and persists the callstack.
  #
  def log_error(msg)
    print_error(msg)

    elog(msg, 'metassh')

    dlog("Call stack:\n#{$@.join("\n")}", 'metassh')
  end

  attr_reader :client # :nodoc:

  protected

  attr_writer :client # :nodoc:

end

end
end
end
end
