# -*- coding: binary -*-
require 'rex/text/color'

module Rex
module Ui
module Text

###
#
# The shell class provides a command-prompt style interface in a
# generic fashion.
#
###
module Shell

  include Rex::Text::Color

  ###
  #
  # This module is meant to be mixed into an input medium class instance as a
  # means of extending it to display a prompt before each call to gets.
  #
  ###
  module InputShell
    attr_accessor :prompt, :output

    def pgets

      output.print(prompt)
      output.flush

      output.prompting
      buf = gets
      output.prompting(false)

      buf
    end
  end

  #
  # Initializes a shell that has a prompt and can be interacted with.
  #
  def initialize(prompt, prompt_char = '>', histfile = nil, framework = nil, name = nil)
    # Set the stop flag to false
    self.stop_flag      = false
    self.disable_output = false
    self.stop_count     = 0
    self.name = name

    # Initialize the prompt
    self.cont_prompt = ' > '
    self.cont_flag = false
    self.prompt = prompt
    self.prompt_char = prompt_char

    self.histfile = histfile
    self.hist_last_saved = 0

    # Static prompt variables
    self.local_hostname = ENV['HOSTNAME'] || try_exec('hostname')&.split('.')&.first&.rstrip || ENV['COMPUTERNAME']
    self.local_username = ENV['USER'] || try_exec('whoami')&.rstrip || ENV['USERNAME']

    self.framework = framework
  end

  def init_tab_complete
    if (self.input and self.input.supports_readline)
      # Unless cont_flag because there's no tab complete for continuation lines
      self.input = Input::Readline.new(lambda { |str| tab_complete(str) unless cont_flag })
      self.input.output = self.output
    end
  end

  #
  # Initializes the user interface input/output classes.
  #
  def init_ui(in_input = nil, in_output = nil)
    # Initialize the input and output methods
    self.input  = in_input
    self.output = in_output

    if (self.input)
      # Extend the input medium as an input shell if the input medium
      # isn't intrinsicly a shell.
      if (self.input.intrinsic_shell? == false)
        self.input.extend(InputShell)
      end

      self.input.output = self.output
    end
  end

  #
  # Resets the user interface handles.
  #
  def reset_ui
    init_ui
  end

  #
  # Sets the log source that should be used for logging input and output.
  #
  def set_log_source(log_source)
    self.log_source = log_source
  end

  #
  # Unsets the log source so that logging becomes disabled.
  #
  def unset_log_source
    set_log_source(nil)
  end

  #
  # Performs tab completion on the supplied string.
  #
  def tab_complete(str)
    return tab_complete_proc(str) if (tab_complete_proc)
  end

  #
  # Run the command processing loop.
  #
  def run(&block)
    begin
      require 'pry'
      # pry history will not be loaded by default when pry is used as a breakpoint like `binding.pry`
      Pry.config.history_load = false
    rescue LoadError
      # Pry is a development dependency, if not available suppressing history_load can be safely ignored.
    end

    with_history_manager_context do
      begin
        while true
          # If the stop flag was set or we've hit EOF, break out
          break if self.stop_flag || self.stop_count > 1

          init_tab_complete
          update_prompt

          line = get_input_line

          # If you have sessions active, this will give you a shot to exit
          # gracefully. If you really are ambitious, 2 eofs will kick this out
          if input.eof? || line == nil
            self.stop_count += 1
            next if self.stop_count > 1

            if block
              block.call('quit')
            elsif respond_to?(:run_single)
              # PseudoShell does not provide run_single
              run_single('quit')
            end

            # If a block was passed in, pass the line to it.  If it returns true,
            # break out of the shell loop.
          elsif block
            break if block.call(line)

            # Otherwise, call what should be an overridden instance method to
            # process the line.
          else
            run_single(line)
            self.stop_count = 0
          end
        end
        # Prevent accidental console quits
      rescue ::Interrupt
        output.print("Interrupt: use the 'exit' command to quit\n")
        retry
      end
    end
  end

  #
  # Stop processing user input.
  #
  def stop
    self.stop_flag = true
  end

  #
  # Checks to see if the shell has stopped.
  #
  def stopped?
    self.stop_flag
  end

  #
  # Change the input prompt.
  #
  # prompt - the actual prompt
  # new_prompt_char the char to append to the prompt
  def update_prompt(new_prompt = self.prompt, new_prompt_char = self.prompt_char)
    if (self.input)
      p = substitute_colors(new_prompt + ' ' + new_prompt_char + ' ', true)

      # Save the prompt before any substitutions
      self.prompt = new_prompt
      self.prompt_char  = new_prompt_char

      # Set the actual prompt to the saved prompt with any substitutions
      # or updates from our output driver, be they color or whatever
      self.input.prompt = self.output.update_prompt(format_prompt(p))
    end
  end

  #
  # Output shortcuts
  #

  #
  # Prints an error message to the output handle.
  #
  def print_error(msg='')
    return if (output.nil?)
    return if (msg.nil?)

    self.on_print_proc.call(msg) if self.on_print_proc
    # Errors are not subject to disabled output
    log_output(output.print_error(msg))
  end

  alias_method :print_bad, :print_error

  #
  # Prints a status message to the output handle.
  #
  def print_status(msg='')
    return if (disable_output == true)

    self.on_print_proc.call(msg) if self.on_print_proc
    log_output(output.print_status(msg))
  end

  #
  # Prints a good message to the output handle.
  #
  def print_good(msg='')
    return if (disable_output == true)

    self.on_print_proc.call(msg) if self.on_print_proc
    log_output(output.print_good(msg))
  end

  #
  # Prints a line of text to the output handle.
  #
  def print_line(msg='')
    return if (disable_output == true)

    self.on_print_proc.call(msg) if self.on_print_proc
    log_output(output.print_line(msg))
  end

  #
  # Prints a warning message to the output handle.
  #
  def print_warning(msg='')
    return if (disable_output == true)

    self.on_print_proc.call(msg) if self.on_print_proc
    log_output(output.print_warning(msg))
  end

  #
  # Prints a raw message to the output handle.
  #
  def print(msg='')
    return if (disable_output == true)
    self.on_print_proc.call(msg) if self.on_print_proc
    log_output(output.print(msg))
  end

  #
  # Whether or not output has been disabled.
  #
  attr_accessor :disable_output
  #
  # The input handle to read user input from.
  #
  attr_reader   :input
  #
  # The output handle to write output to.
  #
  attr_reader   :output

  attr_reader   :prompt, :prompt_char
  attr_accessor :on_command_proc
  attr_accessor :on_print_proc
  attr_accessor :framework
  attr_accessor :history_manager
  attr_accessor :hist_last_saved # the number of history lines when last saved/loaded

  protected

  # Executes the yielded block under the context of a new HistoryManager context. The shell's history will be flushed
  # to disk when no longer interacting with the shell. If no history manager is available, the history will not be persisted.
  def with_history_manager_context
    history_manager = self.history_manager || framework&.history_manager
    return yield unless history_manager

    begin
      history_manager.with_context(history_file: histfile, name: name) do
        self.hist_last_saved = Readline::HISTORY.length

        yield
      end
    ensure
      history_manager.flush
      self.hist_last_saved = Readline::HISTORY.length
    end
  end

  def supports_color?
    true
  end

  #
  # Get a single line of input, following continuation directives as necessary.
  #
  def get_input_line
    line = "\\\n"
    prompt_needs_reset = false

    self.cont_flag = false
    while line =~ /(^|[^\\])\\\s*$/
      # Strip \ and all the trailing whitespace
      line.sub!(/\\\s*/, '')

      if line.length > 0
        # Using update_prompt will overwrite the primary prompt
        input.prompt = output.update_prompt(self.cont_prompt)
        self.cont_flag = true
        prompt_needs_reset = true
      end

      output.input = input
      str = input.pgets
      if str
        line << str
      else
        line = nil
      end

      output.input = nil
      log_output(input.prompt)
    end
    self.cont_flag = false

    if prompt_needs_reset
      # The continuation prompt was used so reset the prompt
      update_prompt
    end

    line
  end

  #
  # Parse a line into an array of arguments.
  #
  def parse_line(line)
    log_input(line)

    line.gsub!(/(\r|\n)/, '')

    begin
      return args = Rex::Parser::Arguments.from_s(line)
    rescue ::ArgumentError
      print_error("Parse error: #{$!}")
    end

    return []
  end

  #
  # Print the prompt, but do not log it.
  #
  def _print_prompt(prompt)
    output.print(prompt)
  end

  #
  # Writes the supplied input to the log source if one has been registered.
  #
  def log_input(buf)
    rlog(buf, log_source) if (log_source)
  end

  #
  # Writes the supplied output to the log source if one has been registered.
  #
  def log_output(buf)
    rlog(buf, log_source) if (log_source)
  end

  #
  # Prompt the user for input if possible. Special edition for use inside commands.
  #
  def prompt_yesno(query)
    p = "#{query} [y/N]"
    old_p = [self.prompt, self.prompt_char]
    update_prompt p, ' '
    /^y/i === get_input_line
  ensure
    update_prompt *old_p
  end

  #
  # Handle prompt substitutions
  #
  def format_prompt(str)
    return str unless framework

    # find the active session
    session = framework.sessions.values.find { |session| session.interacting }
    default = 'unknown'

    formatted = ''
    skip_next = false
    for prefix, spec in str.split('').each_cons(2) do
      if skip_next
        skip_next = false
        next
      end

      unless prefix == '%'
        formatted << prefix
        skip_next = false
        next
      end

      skip_next = true
      if spec == 'T'
        if framework.datastore['PromptTimeFormat']
          strftime_format = framework.datastore['PromptTimeFormat']
        else
          strftime_format = ::Time::DATE_FORMATS[:db].to_s
        end
        formatted << ::Time.now.strftime(strftime_format).to_s
      elsif spec == 'W' && framework.db.active
        formatted << framework.db.workspace.name
      elsif session
        sysinfo = session.respond_to?(:sys) ? session.sys.config.sysinfo : nil

        case spec
        when 'A'
          formatted << (sysinfo.nil? ? default : sysinfo['Architecture'])
        when 'D'
          formatted << (session.respond_to?(:fs) ? session.fs.dir.getwd(refresh: false) : default)
        when 'd'
          formatted << ::Dir.getwd
        when 'H'
          formatted << (sysinfo.nil? ? default : sysinfo['Computer'])
        when 'h'
          formatted << (self.local_hostname || default).chomp
        when 'I'
          formatted << session.tunnel_peer
        when 'i'
          formatted << session.tunnel_local
        when 'M'
          formatted << session.session_type
        when 'S'
          formatted << session.sid.to_s
        when 'U'
          formatted << (session.respond_to?(:sys) ? session.sys.config.getuid(refresh: false) : default)
        when 'u'
          formatted << (self.local_username || default).chomp
        else
          formatted << prefix
          skip_next = false
        end
      else
        case spec
        when 'H'
          formatted << (self.local_hostname || default).chomp
        when 'J'
          formatted << framework.jobs.length.to_s
        when 'U'
          formatted << (self.local_username || default).chomp
        when 'S'
          formatted << framework.sessions.length.to_s
        when 'L'
          formatted << Rex::Socket.source_address
        when 'D'
          formatted << ::Dir.getwd
        else
          formatted << prefix
          skip_next = false
        end
      end
    end

    if str.length > 0 && !skip_next
      formatted << str[-1]
    end

    formatted
  end

  attr_writer   :input, :output # :nodoc:
  attr_writer   :prompt, :prompt_char # :nodoc:
  attr_accessor :stop_flag, :cont_prompt # :nodoc:
  attr_accessor :tab_complete_proc # :nodoc:
  attr_accessor :histfile # :nodoc:
  attr_accessor :log_source, :stop_count # :nodoc:
  attr_accessor :local_hostname, :local_username # :nodoc:
  attr_reader   :cont_flag # :nodoc:
  attr_accessor :name
private

  def try_exec(command)
    begin
      %x{ #{ command } }
    rescue SystemCallError
      nil
    end
  end

  attr_writer   :cont_flag # :nodoc:

end

end end end
