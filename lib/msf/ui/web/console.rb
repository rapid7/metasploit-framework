# -*- coding: binary -*-
require 'rex/ui/text/bidirectional_pipe'
module Msf
module Ui
module Web

###
#
# This class implements a console instance for use by the web interface
#
###

class WebConsole
  attr_accessor :pipe
  attr_accessor :console
  attr_accessor :console_id
  attr_accessor :last_access
  attr_accessor :framework
  attr_accessor :thread

  # Wrapper class in case we need to extend the pipe
  class WebConsolePipe < Rex::Ui::Text::BidirectionalPipe
    def prompting?
      false
    end
  end

  #
  # Provides some overrides for web-based consoles
  #
  module WebConsoleShell

    def supports_color?
      false
    end
  end

  def initialize(framework, console_id, opts={})
    # Configure the framework
    self.framework = framework

    # Configure the ID
    self.console_id = console_id

    # Create a new pipe
    self.pipe = WebConsolePipe.new

    # Create a read subscriber
    self.pipe.create_subscriber('msfweb')

    # Skip database initialization if it is already configured
    if framework.db && framework.db.active
      opts['SkipDatabaseInit'] = true
    end

    # Initialize the console with our pipe
    self.console = Msf::Ui::Console::Driver.new(
      'msf',
      '>',
      opts.merge({
        'Framework'   => self.framework,
        'LocalInput'  => self.pipe,
        'LocalOutput' => self.pipe,
        'AllowCommandPassthru' => true,
        'Resource'    => [],
      })
    )

    self.console.extend(WebConsoleShell)
    self.console.block_command('irb')

    self.thread = framework.threads.spawn("WebConsoleShell", false) { self.console.run }

    update_access()
  end

  def update_access
    self.last_access = Time.now
  end

  def read
    update_access
    self.pipe.read_subscriber('msfweb')
  end

  def write(buf)
    update_access
    self.pipe.write_input(buf)
  end

  def execute(cmd)
    self.console.run_single(cmd)
  end

  def prompt
    self.pipe.prompt
  end

  def tab_complete(cmd)
    if(self.console.active_session)
      return self.console.active_session.console.tab_complete(cmd)
    end
    self.console.tab_complete(cmd)
  end

  def shutdown
    self.pipe.close
    self.thread.kill
  end

  def busy
    self.console.busy
  end

  def session_detach
    if(self.console.active_session)
      #background interactive meterpreter channel
      if(self.console.active_session.respond_to?('channels'))
        self.console.active_session.channels.each_value do |ch|
          if(ch.respond_to?('interacting') && ch.interacting)
            ch.detach()
            return
          end
        end
      end
      #background session
      self.console.active_session.completed = true
      self.console.active_session.detach()
    end
  end

  def session_kill
    self.thread.raise(Interrupt)
  end

  def active_module
    self.console.active_module
  end

  def active_module=(val)
    self.console.active_module = val
  end

end


end
end
end

