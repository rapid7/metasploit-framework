# -*- coding: binary -*-
require 'rex/ui'

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
  def initialize(prompt, prompt_char = '>', histfile = nil, framework = nil)
    # Set the stop flag to false
    self.stop_flag      = false
    self.disable_output = false
    self.stop_count     = 0

    # Initialize the prompt
    self.cont_prompt = ' > '
    self.cont_flag = false
    self.prompt = prompt
    self.prompt_char = prompt_char

    self.histfile = histfile
    self.hist_last_saved = 0

    self.framework = framework
  end

  def init_tab_complete
    if (self.input and self.input.supports_readline)
      # Unless cont_flag because there's no tab complete for continuation lines
      self.input = Input::Readline.new(lambda { |str| tab_complete(str) unless cont_flag })
      if Readline::HISTORY.length == 0 and histfile and File.exist?(histfile)
        File.readlines(histfile).each { |e|
          Readline::HISTORY << e.chomp
        }
        self.hist_last_saved = Readline::HISTORY.length
      end
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
          run_single("quit")

        # If a block was passed in, pass the line to it.  If it returns true,
        # break out of the shell loop.
        elsif block
          break if block.call(line)

        # Otherwise, call what should be an overriden instance method to
        # process the line.
        else
          ret = run_single(line)
          # don't bother saving lines that couldn't be found as a
          # command, create the file if it doesn't exist, don't save dupes
          if ret && self.histfile && line != @last_line
            File.open(self.histfile, "a+") { |f| f.puts(line) }
            @last_line = line
          end
          self.stop_count = 0
        end

      end
    # Prevent accidental console quits
    rescue ::Interrupt
      output.print("Interrupt: use the 'exit' command to quit\n")
      retry
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
      p = new_prompt + ' ' + new_prompt_char + ' '

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

protected

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

    if str.include?('%J')
      str.gsub!('%J', framework.jobs.length.to_s)
    end

    if str.include?('%T')
      t = Time.now
      # This %T is the strftime shorthand for %H:%M:%S
      format = framework.datastore['PromptTimeFormat'] || '%T'
      t = t.strftime(format)
      # This %T is the marker in the prompt where we need to place the time
      str.gsub!('%T', t.to_s)
    end

    if str.include?('%W') && framework.db.active
      str.gsub!('%W', framework.db.workspace.name)
    end

    if session
      default = 'unknown'
      sysinfo = session.respond_to?(:sys) ? session.sys.config.sysinfo : nil

      if str.include?('%A')
        str.gsub!('%A', (sysinfo.nil? ? default : sysinfo['Architecture']))
      end

      if str.include?('%D')
        str.gsub!('%D', (session.respond_to?(:fs) ? session.fs.dir.getwd(refresh: false) : default))
      end

      if str.include?('%H')
        str.gsub!('%H', (sysinfo.nil? ? default : sysinfo['Computer']))
        end

      if str.include?('%S')
        str.gsub!('%S', session.sid.to_s)
      end

      if str.include?('%U')
        str.gsub!('%U', (session.respond_to?(:sys) ? session.sys.config.getuid(refresh: false) : default))
      end
    else
      if str.include?('%H')
        hostname = ENV['HOSTNAME'] || `hostname`.split('.')[0] ||
            ENV['COMPUTERNAME'] || 'unknown'

        str.gsub!('%H', hostname.chomp)
      end

      if str.include?('%U')
        user = ENV['USER'] || `whoami` || ENV['USERNAME'] || 'unknown'
        str.gsub!('%U', user.chomp)
      end

      if str.include?('%S')
        str.gsub!('%S', framework.sessions.length.to_s)
      end

      if str.include?('%L')
        str.gsub!('%L', Rex::Socket.source_address)
      end

      if str.include?('%D')
        str.gsub!('%D', ::Dir.getwd)
      end
    end

    str
  end

  attr_writer   :input, :output # :nodoc:
  attr_writer   :prompt, :prompt_char # :nodoc:
  attr_accessor :stop_flag, :cont_prompt # :nodoc:
  attr_accessor :tab_complete_proc # :nodoc:
  attr_accessor :histfile # :nodoc:
  attr_accessor :hist_last_saved # the number of history lines when last saved/loaded
  attr_accessor :log_source, :stop_count # :nodoc:
  attr_reader   :cont_flag # :nodoc:

private

  attr_writer   :cont_flag # :nodoc:

end

###
#
# Pseudo-shell interface that simply includes the Shell mixin.
#
###
class PseudoShell
  include Shell
end


end end end

