# -*- coding: binary -*-

#
# Standard library
#
require 'pp'
require 'shellwords'

#
# Project
#

require 'rex/ui'

module Rex
module Ui
module Text

###
#
# The dispatcher shell class is designed to provide a generic means
# of processing various shell commands that may be located in
# different modules or chunks of codes.  These chunks are referred
# to as command dispatchers.  The only requirement for command dispatchers is
# that they prefix every method that they wish to be mirrored as a command
# with the cmd_ prefix.
#
###
module DispatcherShell
  extend ActiveSupport::Concern

  #
  # CONSTANT
  #

  # Captures trailing spaces at the end of a line.
  TRAILING_SPACE_REGEXP = /\s+$/

  module ClassMethods
    # Breaks up the line into words and attempts to repair unclosed double quotes so that {#tab_complete} will work when
    # only an opening double quote is present.
    #
    # @param line [String] line being tab completed.
    # @return [Array<String>]
    # @raise [ArgumentError] if `line` cannot be broken up into words (because unclosed double quotes cannot be
    #   repaired)
    def shell_words(line)
      retrying = false

      # Split the line up using Shellwords to support quoting and escapes
      begin
        Shellwords.split(line)
      rescue ::ArgumentError => error
        unless retrying
          # append a double quote to see if the line can be made parseable
          line += '"'
          retrying = true
          retry
        else
          # couldn't fix the unclosed double quotes, so no shell words were parseable
          raise error
        end
      end
    end
  end

  ###
  #
  # Empty template base class for command dispatchers.
  #
  ###
  module CommandDispatcher

    #
    # Initializes the command dispatcher mixin.
    #
    def initialize(shell)
      self.shell = shell
      self.tab_complete_items = []
    end

    #
    # Returns {} for an empty set of commands.
    #
    # This method should be overridden to return a Hash with command
    # names for keys and brief help text for values.
    #
    def commands
      {}
    end

    #
    # Returns an empty set of commands.
    #
    # This method should be overridden if the dispatcher has commands that
    # should be treated as deprecated. Deprecated commands will not show up in
    # help and will not tab-complete, but will still be callable.
    #
    def deprecated_commands
      []
    end

    # @!method flush
    #   Flush the output `IO` attached to {#shell}.
    #
    #   @return [void]
    #
    # @!method print
    #   Prints message to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_error
    #   Prints error to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_good
    #   Prints a good message to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_line
    #   Prints message followed by a newline to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_status
    #   Prints a status message to {#shell}.
    #
    #   @return [void]
    #
    # @!method print_warning
    #   Prints a warning message to {#shell}.
    #
    #   @return [void]
    #
    # @!method tty?
    #   Whether the {#shell} is attached to a TTY.
    #
    #   @return [true] if {#shell} is attached to a TTY.
    #   @return [false] if {#shell} is not attached to a TTY or a mix of a TTY and something other non-TTY `IO`.
    #
    # @!method width
    #   The terminal width.
    #
    #   @return [80] if {#shell} is not connected to a TTY.
    #   @return [Integer] if {#shell} is connected to a TTY.
    delegate :flush,
             :print,
             :print_error,
             :print_good,
             :print_line,
             :print_status,
             :print_warning,
             :tty?,
             :width,
             to: :shell

    #
    # Print a warning that the called command is deprecated and optionally
    # forward to the replacement +method+ (useful for when commands are
    # renamed).
    #
    def deprecated_cmd(method=nil, *args)
      cmd = caller[0].match(/`cmd_(.*)'/)[1]
      print_error "The #{cmd} command is DEPRECATED"
      if cmd == "db_autopwn"
        print_error "See http://r-7.co/xY65Zr instead"
      elsif method and self.respond_to?("cmd_#{method}")
        print_error "Use #{method} instead"
        self.send("cmd_#{method}", *args)
      end
    end

    def deprecated_help(method=nil)
      cmd = caller[0].match(/`cmd_(.*)_help'/)[1]
      print_error "The #{cmd} command is DEPRECATED"
      if cmd == "db_autopwn"
        print_error "See http://r-7.co/xY65Zr instead"
      elsif method and self.respond_to?("cmd_#{method}_help")
        print_error "Use 'help #{method}' instead"
        self.send("cmd_#{method}_help")
      end
    end

    #
    # Wraps shell.update_prompt
    #
    def update_prompt(prompt=nil, prompt_char = nil, mode = false)
      shell.update_prompt(prompt, prompt_char, mode)
    end

    def cmd_help_help
      print_line "There's only so much I can do"
    end

    #
    # Displays the help banner.  With no arguments, this is just a list of
    # all commands grouped by dispatcher.  Otherwise, tries to use a method
    # named cmd_<cmd>_help for the first dispatcher that has a command
    # named `cmd`.  If no such method exists, uses `cmd` as a regex to
    # compare against each enstacked dispatcher's name and dumps commands
    # of any that match.
    #
    def cmd_help(cmd=nil, *ignored)
      if cmd
        help_found = false
        cmd_found = false
        shell.dispatcher_stack.each do |dispatcher|
          next unless dispatcher.respond_to?(:commands)
          next if (dispatcher.commands.nil?)
          next if (dispatcher.commands.length == 0)

          if dispatcher.respond_to?("cmd_#{cmd}")
            cmd_found = true
            break unless dispatcher.respond_to? "cmd_#{cmd}_help"
            dispatcher.send("cmd_#{cmd}_help")
            help_found = true
            break
          end
        end

        unless cmd_found
          # We didn't find a cmd, try it as a dispatcher name
          shell.dispatcher_stack.each do |dispatcher|
            if dispatcher.name =~ /#{cmd}/i
              print_line(dispatcher.help_to_s)
              cmd_found = help_found = true
            end
          end
        end
        print_error("No help for #{cmd}, try -h") if cmd_found and not help_found
        print_error("No such command") if not cmd_found
      else
        print(shell.help_to_s)
      end
    end

    #
    # Tab completion for the help command
    #
    # By default just returns a list of all commands in all dispatchers.
    #
    def cmd_help_tabs(str, words)
      return [] if words.length > 1

      tabs = []
      shell.dispatcher_stack.each { |dispatcher|
        tabs += dispatcher.commands.keys
      }
      return tabs
    end

    alias cmd_? cmd_help

    #
    # Return a pretty, user-readable table of commands provided by this
    # dispatcher.
    #
    def help_to_s(opts={})
      # If this dispatcher has no commands, we can't do anything useful.
      return "" if commands.nil? or commands.length == 0

      # Display the commands
      tbl = Table.new(
        'Header'  => "#{self.name} Commands",
        'Indent'  => opts['Indent'] || 4,
        'Columns' =>
          [
            'Command',
            'Description'
          ],
        'ColProps' =>
          {
            'Command' =>
              {
                'MaxWidth' => 12
              }
          })

      commands.sort.each { |c|
        tbl << c
      }

      return "\n" + tbl.to_s + "\n"
    end

    #
    # No tab completion items by default
    #
    attr_accessor :shell, :tab_complete_items

    #
    # Provide a generic tab completion for file names.
    #
    # If the only completion is a directory, this descends into that directory
    # and continues completions with filenames contained within.
    #
    def tab_complete_filenames(str, words)
      matches = ::Readline::FILENAME_COMPLETION_PROC.call(str)
      if matches and matches.length == 1 and File.directory?(matches[0])
        dir = matches[0]
        dir += File::SEPARATOR if dir[-1,1] != File::SEPARATOR
        matches = ::Readline::FILENAME_COMPLETION_PROC.call(dir)
      end
      matches
    end

  end

  #
  # DispatcherShell derives from shell.
  #
  include Shell

  #
  # Initialize the dispatcher shell.
  #
  def initialize(prompt, prompt_char = '>', histfile = nil, framework = nil)
    super

    # Initialze the dispatcher array
    self.dispatcher_stack = []

    # Initialize the tab completion array
    self.tab_words = []
    self.on_command_proc = nil
  end

  #
  # This method accepts the entire line of text from the Readline
  # routine, stores all completed words, and passes the partial
  # word to the real tab completion function. This works around
  # a design problem in the Readline module and depends on the
  # Readline.basic_word_break_characters variable being set to \x00
  #
  def tab_complete(line)
    begin
      shell_words = self.class.shell_words(line)
    rescue ::ArgumentError => error
      print_error("#{error.class}: #{error}")

      []
    else
      # `Shellwords.split` will not return an empty word after the space so, need to determine if the trailing spaces
      # were captured by escapes ("one two\\ " -> ["one", "two"]) or if its a separator space
      # ("one two " -> ["one", "two"], but should be ["one", "two", ""]) and an empty word should be appended to
      # shell_words.
      line_trailing_spaces = line[TRAILING_SPACE_REGEXP]

      # if the string as a whole has no trailing spaces, then there's no need to check for trailing spaces on the last
      # shell word because the shell splitting will match the desired words for tab completion
      if line_trailing_spaces
        last_shell_word = shell_words.last
        last_shell_word_trailing_spaces = last_shell_word[TRAILING_SPACE_REGEXP]

        if last_shell_word_trailing_spaces.nil? || last_shell_word_trailing_spaces.length < line_trailing_spaces.length
          shell_words << ''
        end
      end

      # re-escape the shell words or after tab completing an escaped string, then the next tab completion will strip
      # the escaping
      escaped_shell_words = shell_words.collect { |shell_word|
        # don't escape the empty word added for tab completion as the tab completers are written to check for an empty
        # partial word to indicate this situation.  If '' is shell escaped it would become "''".
        if shell_word.empty?
          ''
        else
          Shellwords.escape(shell_word)
        end
      }

      # Place the word list into an instance variable
      self.tab_words = escaped_shell_words

      # Pop the last word and pass it to the real method
      tab_complete_stub(tab_words.pop)
    end
  end

  # Performs tab completion of a command, if supported
  # Current words can be found in self.tab_words
  #
  def tab_complete_stub(partial_word)
    if partial_word
      items = []

      dispatcher_stack.each { |dispatcher|
        # command completion
        if tab_words.empty? && dispatcher.respond_to?(:commands)
          items.concat(dispatcher.commands.keys)
        end

        # If the dispatcher exports a tab completion function, use it
        if dispatcher.respond_to? :tab_complete_helper
          dispatcher_items = dispatcher.tab_complete_helper(partial_word, tab_words)
        # otherwise use the default implementation of tab completion for dispatchers
        else
          dispatcher_items = tab_complete_helper(dispatcher, partial_word, tab_words)
        end

        # A nil response indicates no optional arguments
        if dispatcher_items.nil?
          if items.empty?
            items << ''
          end
        else
          # Otherwise we add the completion items to the list
          items.concat(dispatcher_items)
        end
      }

      matching_items = items.select { |item|
        item.start_with? partial_word
      }

      matching_items.collect { |matching_item|
        # Prepend the rest of the command as the underlying code allows for line replacement
        completed_words = [*tab_words, matching_item]
        # caller expected completed lines and not completed word lists
        completed_words.join(' ')
      }
    else
      nil
    end
  end

  #
  # Provide command-specific tab completion
  #
  def tab_complete_helper(dispatcher, str, words)
    items = []

    tabs_meth = "cmd_#{words[0]}_tabs"
    # Is the user trying to tab complete one of our commands?
    if (dispatcher.commands.include?(words[0]) and dispatcher.respond_to?(tabs_meth))
      res = dispatcher.send(tabs_meth, str, words)
      return [] if res.nil?
      items.concat(res)
    else
      # Avoid the default completion list for known commands
      return []
    end

    return items
  end

  #
  # Run a single command line.
  #
  def run_single(line)
    arguments = parse_line(line)
    method    = arguments.shift
    found     = false
    error     = false

    # If output is disabled output will be nil
    output.reset_color if (output)

    if (method)
      entries = dispatcher_stack.length

      dispatcher_stack.each { |dispatcher|
        next if not dispatcher.respond_to?('commands')

        begin
          if (dispatcher.commands.has_key?(method) or dispatcher.deprecated_commands.include?(method))
            self.on_command_proc.call(line.strip) if self.on_command_proc
            run_command(dispatcher, method, arguments)
            found = true
          end
        rescue
          error = $!

          print_error(
            "Error while running command #{method}: #{$!}" +
            "\n\nCall stack:\n#{$@.join("\n")}")
        rescue ::Exception
          error = $!

          print_error(
            "Error while running command #{method}: #{$!}")
        end

        # If the dispatcher stack changed as a result of this command,
        # break out
        break if (dispatcher_stack.length != entries)
      }

      if (found == false and error == false)
        unknown_command(method, line)
      end
    end

    return found
  end

  #
  # Runs the supplied command on the given dispatcher.
  #
  def run_command(dispatcher, method, arguments)
    self.busy = true

    if(blocked_command?(method))
      print_error("The #{method} command has been disabled.")
    else
      dispatcher.send('cmd_' + method, *arguments)
    end
    self.busy = false
  end

  #
  # If the command is unknown...
  #
  def unknown_command(method, line)
    print_error("Unknown command: #{method}.")
  end

  #
  # Push a dispatcher to the front of the stack.
  #
  def enstack_dispatcher(dispatcher)
    self.dispatcher_stack.unshift(inst = dispatcher.new(self))

    inst
  end

  #
  # Pop a dispatcher from the front of the stacker.
  #
  def destack_dispatcher
    self.dispatcher_stack.shift
  end

  #
  # Adds the supplied dispatcher to the end of the dispatcher stack so that
  # it doesn't affect any enstack'd dispatchers.
  #
  def append_dispatcher(dispatcher)
    inst = dispatcher.new(self)
    self.dispatcher_stack.each { |disp|
      if (disp.name == inst.name)
        raise RuntimeError.new("Attempting to load already loaded dispatcher #{disp.name}")
      end
    }
    self.dispatcher_stack.push(inst)

    inst
  end

  #
  # Removes the supplied dispatcher instance.
  #
  def remove_dispatcher(name)
    self.dispatcher_stack.delete_if { |inst|
      (inst.name == name)
    }
  end

  #
  # Returns the current active dispatcher
  #
  def current_dispatcher
    self.dispatcher_stack[0]
  end

  #
  # Return a readable version of a help banner for all of the enstacked
  # dispatchers.
  #
  # See +CommandDispatcher#help_to_s+
  #
  def help_to_s(opts = {})
    str = ''

    dispatcher_stack.reverse.each { |dispatcher|
      str << dispatcher.help_to_s
    }

    return str
  end


  #
  # Returns nil for an empty set of blocked commands.
  #
  def blocked_command?(cmd)
    return false if not self.blocked
    self.blocked.has_key?(cmd)
  end

  #
  # Block a specific command
  #
  def block_command(cmd)
    self.blocked ||= {}
    self.blocked[cmd] = true
  end

  #
  # Unblock a specific command
  #
  def unblock_command(cmd)
    self.blocked || return
    self.blocked.delete(cmd)
  end


  attr_accessor :dispatcher_stack # :nodoc:
  attr_accessor :tab_words # :nodoc:
  attr_accessor :busy # :nodoc:
  attr_accessor :blocked # :nodoc:

end

end
end
end
