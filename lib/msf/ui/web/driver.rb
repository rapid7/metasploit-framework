# -*- coding: binary -*-
require 'rex/proto/http'
require 'msf/core'
require 'msf/base'
require 'msf/ui'

module Msf
module Ui
module Web

require 'rex/io/bidirectional_pipe'
require 'msf/ui/web/console'


###
#
# This class implements a user interface driver on a web interface.
#
###
class Driver < Msf::Ui::Driver


  attr_accessor :framework # :nodoc:
  attr_accessor :consoles # :nodoc:
  attr_accessor :sessions # :nodoc:
  attr_accessor :last_console # :nodoc:

  ConfigCore  = "framework/core"
  ConfigGroup = "framework/ui/web"

  #
  # Initializes a web driver instance and prepares it for listening to HTTP
  # requests.  The constructor takes a hash of options that can control how
  # the web server will operate.
  #
  def initialize(opts = {})
    # Call the parent
    super()

    # Set the passed options hash for referencing later on.
    self.opts = opts

    self.consoles = {}
    self.sessions = {}

    if(opts[:framework])
      self.framework = opts[:framework]
    else
      # Initialize configuration
      Msf::Config.init

      # Initialize logging
      initialize_logging

      # Initialize attributes
      self.framework = Msf::Simple::Framework.create
    end

    # Initialize the console count
    self.last_console = 0
  end

  def create_console(opts={})
    # Destroy any unused consoles
    clean_consoles

    console = WebConsole.new(self.framework, self.last_console, opts)
    self.last_console += 1
    self.consoles[console.console_id.to_s] = console
    console.console_id.to_s
  end

  def destroy_console(cid)
    con = self.consoles[cid]
    if(con)
      con.shutdown
      self.consoles.delete(cid)
    end
  end


  def write_console(id, buf)
    self.consoles[id] ? self.consoles[id].write(buf) : nil
  end

  def read_console(id)
    self.consoles[id] ? self.consoles[id].read() : nil
  end

  def clean_consoles(timeout=300)
    self.consoles.each_pair do |id, con|
      if (con.last_access + timeout < Time.now)
        con.shutdown
        self.consoles.delete(id)
      end
    end
  end

  def write_session(id, buf)
    ses = self.framework.sessions[id]
    return if not ses
    return if not ses.user_input
    ses.user_input.put(buf)
  end

  def read_session(id)
    ses = self.framework.sessions[id]
    return if not ses
    return if not ses.user_output
    ses.user_output.read_subscriber('session_reader')
  end

  # Detach the session from an existing input/output pair
  def connect_session(id)

    # Ignore invalid sessions
    ses = self.framework.sessions[id]
    return if not ses

    # Has this session already been detached?
    if (ses.user_output)
      return if ses.user_output.has_subscriber?('session_reader')
    end

    # Create a new pipe
    spipe = WebConsole::WebConsolePipe.new
    spipe.input = spipe.pipe_input

    # Create a read subscriber
    spipe.create_subscriber('session_reader')

    framework.threads.spawn("ConnectSessionInteraction", false) do
      ses.interact(spipe.input, spipe)
    end
  end

  def sessions
    self.framework.sessions
  end

  #
  # Stub
  #
  def run
    true
  end

protected

  attr_accessor :opts      # :nodoc:

  #
  # Initializes logging for the web interface
  #
  def initialize_logging
    level = (opts['LogLevel'] || 0).to_i

    Msf::Logging.enable_log_source(LogSource, level)
  end

end

end
end
end

