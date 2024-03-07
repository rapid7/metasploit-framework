# -*- coding: binary -*-
module Rex
module Post
module Sql
module Ui
module Console

###
#
# Mixin that is meant to extend a sql client class in a
# manner that adds interactive capabilities.
#
###
module InteractiveSqlClient

  include Rex::Ui::Interactive

  #
  # Interacts with self.
  #
  def _interact
    while self.interacting
      sql_input = _multiline_with_fallback
      self.interacting = (sql_input[:status] != :exit)

      if sql_input[:status] == :help
        client_dispatcher.query_interactive_help
      end

      # We need to check that the user is still interacting, i.e. if ctrl+z is triggered when requesting user input
      break unless (self.interacting && sql_input[:result])

      self.on_command_proc.call(sql_input[:result].strip) if self.on_command_proc

      formatted_query = client_dispatcher.process_query(query: sql_input[:result])
      print_status "Executing query: #{formatted_query}"
      client_dispatcher.cmd_query(formatted_query)
    end
  end

  #
  # Called when an interrupt is sent.
  #
  def _interrupt
    prompt_yesno('Terminate interactive SQL prompt?')
  end

  #
  # Suspends interaction with the interactive REPL interpreter
  #
  def _suspend
    if (prompt_yesno('Background interactive SQL prompt?') == true)
      self.interacting = false
    end
  end

  #
  # We don't need to do any clean-up when finishing the interaction with the REPL
  #
  def _interact_complete
    # noop
  end

  def _winch
    # noop
  end

  # Try getting multi-line input support provided by Reline, fall back to Readline.
  def _multiline_with_fallback
    query = _multiline
    query = _fallback if query[:status] == :fail

    query
  end

  def _multiline
    begin
      require 'reline' unless defined?(::Reline)
    rescue ::LoadError => e
      elog('Failed to load Reline', e)
      return { status: :fail, errors: [e] }
    end

    stop_words = %w[stop s exit e end quit q].freeze
    help_words = %w[help h].freeze

    finished = false
    help = false
    begin
      result = nil
      prompt_proc_before = ::Reline.prompt_proc
      ::Reline.prompt_proc = proc { |line_buffer| line_buffer.each_with_index.map { |_line, i| i > 0 ? 'SQL *> ' : 'SQL >> ' } }

      # We want to do this in a loop
      # multiline_input is the whole string that the user has input, not just the current line.
      raw_query = ::Reline.readmultiline('SQL >> ', use_history = true) do |multiline_input|
        # The user pressed ctrl + c or ctrl + z and wants to background our SQL prompt
        unless self.interacting
          result = { status: :exit, result: nil }
          next true
        end

        # When the user has pressed the enter key with no input, don't run any queries;
        # simply give them a new prompt on a new line.
        if multiline_input.chomp.empty?
          result = { status: :success, result: nil }
          next true
        end

        if multiline_input.split.count == 1
          # In the case only a stop word was input, exit out of the REPL shell
          finished = stop_words.include?(multiline_input.split.last)
          # In the case when only a help word was input call the help command
          help = help_words.include?(multiline_input.split.last)
        end

        finished || help || multiline_input.split.last&.end_with?(';')
      end
    rescue ::StandardError => e
      elog('Failed to get multi-line SQL query from user', e)
    ensure
      ::Reline.prompt_proc = prompt_proc_before
    end

    if result
      return result
    end

    if help
      return { status: :help, result: nil }
    end

    if finished
      self.interacting = false
      print_status 'Exiting Interactive mode.'
      return { status: :exit, result: nil }
    end

    { status: :success, result: raw_query }
  end

  def _fallback
    stop_words = %w[stop s exit e end quit q].freeze
    line_buffer = []
    while (line = ::Readline.readline(prompt = line_buffer.empty? ? 'SQL >> ' : 'SQL *> ', add_history = true))
      return { status: :exit, result: nil } unless self.interacting

      if stop_words.include? line.chomp.downcase
        self.interacting = false
        print_status 'Exiting Interactive mode.'
        return { status: :exit, result: nil }
      end

      next if line.empty?

      line_buffer.append line

      break if line.end_with? ';'
    end

    { status: :success, result: line_buffer.join }
  end

  attr_accessor :on_log_proc, :client_dispatcher

end
end
end
end
end
end
