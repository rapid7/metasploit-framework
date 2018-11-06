# -*- coding: utf-8 -*-
##
# Pry is a powerful alternative to the standard IRB shell for Ruby. It
# features syntax highlighting, a flexible plugin architecture, runtime
# invocation and source and documentation browsing.
#
# Pry can be started similar to other command line utilities by simply running
# the following command:
#
#     pry
#
# Once inside Pry you can invoke the help message:
#
#     help
#
# This will show a list of available commands and their usage. For more
# information about Pry you can refer to the following resources:
#
# * http://pryrepl.org/
# * https://github.com/pry/pry
# * the IRC channel, which is #pry on the Freenode network
#

class Pry
  attr_accessor :binding_stack
  attr_accessor :custom_completions
  attr_accessor :eval_string
  attr_accessor :backtrace
  attr_accessor :suppress_output
  attr_accessor :last_result
  attr_accessor :last_file
  attr_accessor :last_dir

  attr_reader :last_exception
  attr_reader :command_state
  attr_reader :exit_value
  attr_reader :input_array
  attr_reader :output_array
  attr_reader :config

  extend Pry::Config::Convenience
  config_shortcut(*Pry::Config.shortcuts)
  EMPTY_COMPLETIONS = [].freeze

  # Create a new {Pry} instance.
  # @param [Hash] options
  # @option options [#readline] :input
  #   The object to use for input.
  # @option options [#puts] :output
  #   The object to use for output.
  # @option options [Pry::CommandBase] :commands
  #   The object to use for commands.
  # @option options [Hash] :hooks
  #   The defined hook Procs.
  # @option options [Array<Proc>] :prompt
  #   The array of Procs to use for prompts.
  # @option options [Proc] :print
  #   The Proc to use for printing return values.
  # @option options [Boolean] :quiet
  #   Omit the `whereami` banner when starting.
  # @option options [Array<String>] :backtrace
  #   The backtrace of the session's `binding.pry` line, if applicable.
  # @option options [Object] :target
  #   The initial context for this session.
  def initialize(options={})
    @binding_stack = []
    @indent        = Pry::Indent.new
    @command_state = {}
    @eval_string   = ""
    @backtrace     = options.delete(:backtrace) || caller
    target = options.delete(:target)
    @config = Pry::Config.new
    config.merge!(options)
    push_prompt(config.prompt)
    @input_array  = Pry::HistoryArray.new config.memory_size
    @output_array = Pry::HistoryArray.new config.memory_size
    @custom_completions = config.command_completions
    set_last_result nil
    @input_array << nil
    push_initial_binding(target)
    exec_hook(:when_started, target, options, self)
  end

  # The current prompt.
  # This is the prompt at the top of the prompt stack.
  #
  # @example
  #    self.prompt = Pry::SIMPLE_PROMPT
  #    self.prompt # => Pry::SIMPLE_PROMPT
  #
  # @return [Array<Proc>] Current prompt.
  def prompt
    prompt_stack.last
  end

  def prompt=(new_prompt)
    if prompt_stack.empty?
      push_prompt new_prompt
    else
      prompt_stack[-1] = new_prompt
    end
  end

  # Initialize this instance by pushing its initial context into the binding
  # stack. If no target is given, start at the top level.
  def push_initial_binding(target=nil)
    push_binding(target || Pry.toplevel_binding)
  end

  # The currently active `Binding`.
  # @return [Binding] The currently active `Binding` for the session.
  def current_binding
    binding_stack.last
  end
  alias current_context current_binding # support previous API

  # Push a binding for the given object onto the stack. If this instance is
  # currently stopped, mark it as usable again.
  def push_binding(object)
    @stopped = false
    binding_stack << Pry.binding_for(object)
  end

  #
  # Generate completions.
  #
  # @param [String] str
  #   What the user has typed so far
  #
  # @return [Array<String>]
  #   Possible completions
  #
  def complete(str)
    return EMPTY_COMPLETIONS unless config.completer
    Pry.critical_section do
      completer = config.completer.new(config.input, self)
      completer.call str, target: current_binding, custom_completions: custom_completions.call.push(*sticky_locals.keys)
    end
  end

  #
  # Injects a local variable into the provided binding.
  #
  # @param [String] name
  #   The name of the local to inject.
  #
  # @param [Object] value
  #   The value to set the local to.
  #
  # @param [Binding] b
  #   The binding to set the local on.
  #
  # @return [Object]
  #   The value the local was set to.
  #
  def inject_local(name, value, b)
    value = Proc === value ? value.call : value
    if b.respond_to?(:local_variable_set)
      b.local_variable_set name, value
    else # < 2.1
      begin
        Pry.current[:pry_local] = value
        b.eval "#{name} = ::Pry.current[:pry_local]"
      ensure
        Pry.current[:pry_local] = nil
      end
    end
  end

  undef :memory_size if method_defined? :memory_size
  # @return [Integer] The maximum amount of objects remembered by the inp and
  #   out arrays. Defaults to 100.
  def memory_size
    @output_array.max_size
  end

  undef :memory_size= if method_defined? :memory_size=
  def memory_size=(size)
    @input_array  = Pry::HistoryArray.new(size)
    @output_array = Pry::HistoryArray.new(size)
  end

  # Inject all the sticky locals into the current binding.
  def inject_sticky_locals!
    sticky_locals.each_pair do |name, value|
      inject_local(name, value, current_binding)
    end
  end

  # Add a sticky local to this Pry instance.
  # A sticky local is a local that persists between all bindings in a session.
  # @param [Symbol] name The name of the sticky local.
  # @yield The block that defines the content of the local. The local
  #   will be refreshed at each tick of the repl loop.
  def add_sticky_local(name, &block)
    config.extra_sticky_locals[name] = block
  end

  def sticky_locals
    { _in_: input_array,
      _out_: output_array,
      _pry_: self,
      _ex_: last_exception && last_exception.wrapped_exception,
      _file_: last_file,
      _dir_: last_dir,
      _: proc { last_result },
      __: proc { output_array[-2] }
    }.merge(config.extra_sticky_locals)
  end

  # Reset the current eval string. If the user has entered part of a multiline
  # expression, this discards that input.
  def reset_eval_string
    @eval_string = ""
  end

  # Pass a line of input to Pry.
  #
  # This is the equivalent of `Binding#eval` but with extra Pry!
  #
  # In particular:
  # 1. Pry commands will be executed immediately if the line matches.
  # 2. Partial lines of input will be queued up until a complete expression has
  #    been accepted.
  # 3. Output is written to `#output` in pretty colours, not returned.
  #
  # Once this method has raised an exception or returned false, this instance
  # is no longer usable. {#exit_value} will return the session's breakout
  # value if applicable.
  #
  # @param [String?] line The line of input; `nil` if the user types `<Ctrl-D>`
  # @option options [Boolean] :generated Whether this line was generated automatically.
  #   Generated lines are not stored in history.
  # @return [Boolean] Is Pry ready to accept more input?
  # @raise [Exception] If the user uses the `raise-up` command, this method
  #   will raise that exception.
  def eval(line, options={})
    return false if @stopped

    exit_value = nil
    exception = catch(:raise_up) do
      exit_value = catch(:breakout) do
        handle_line(line, options)
        # We use 'return !@stopped' here instead of 'return true' so that if
        # handle_line has stopped this pry instance (e.g. by opening _pry_.repl and
        # then popping all the bindings) we still exit immediately.
        return !@stopped
      end
      exception = false
    end

    @stopped = true
    @exit_value = exit_value

    # TODO: make this configurable?
    raise exception if exception
    return false
  end

  def handle_line(line, options)
    if line.nil?
      config.control_d_handler.call(@eval_string, self)
      return
    end

    ensure_correct_encoding!(line)
    Pry.history << line unless options[:generated]

    @suppress_output = false
    inject_sticky_locals!
    begin
      if !process_command_safely(line)
        @eval_string << "#{line.chomp}\n" if !line.empty? || !@eval_string.empty?
      end
    rescue RescuableException => e
      self.last_exception = e
      result = e

      Pry.critical_section do
        show_result(result)
      end
      return
    end

    # This hook is supposed to be executed after each line of ruby code
    # has been read (regardless of whether eval_string is yet a complete expression)
    exec_hook :after_read, eval_string, self

    begin
      complete_expr = Pry::Code.complete_expression?(@eval_string)
    rescue SyntaxError => e
      output.puts "SyntaxError: #{e.message.sub(/.*syntax error, */m, '')}"
      reset_eval_string
    end

    if complete_expr
      if @eval_string =~ /;\Z/ || @eval_string.empty? || @eval_string =~ /\A *#.*\n\z/
        @suppress_output = true
      end

      # A bug in jruby makes java.lang.Exception not rescued by
      # `rescue Pry::RescuableException` clause.
      #
      # * https://github.com/pry/pry/issues/854
      # * https://jira.codehaus.org/browse/JRUBY-7100
      #
      # Until that gets fixed upstream, treat java.lang.Exception
      # as an additional exception to be rescued explicitly.
      #
      # This workaround has a side effect: java exceptions specified
      # in `Pry.config.exception_whitelist` are ignored.
      jruby_exceptions = []
      if Pry::Helpers::BaseHelpers.jruby?
        jruby_exceptions << Java::JavaLang::Exception
      end

      begin
        # Reset eval string, in case we're evaluating Ruby that does something
        # like open a nested REPL on this instance.
        eval_string = @eval_string
        reset_eval_string

        result = evaluate_ruby(eval_string)
      rescue RescuableException, *jruby_exceptions => e
        # Eliminate following warning:
        # warning: singleton on non-persistent Java type X
        # (http://wiki.jruby.org/Persistence)
        if Pry::Helpers::BaseHelpers.jruby? && e.class.respond_to?('__persistent__')
          e.class.__persistent__ = true
        end
        self.last_exception = e
        result = e
      end

      Pry.critical_section do
        show_result(result)
      end
    end

    throw(:breakout) if current_binding.nil?
  end
  private :handle_line

  # Potentially deprecated — Use `Pry::REPL.new(pry, :target => target).start`
  # (If nested sessions are going to exist, this method is fine, but a goal is
  # to come up with an alternative to nested sessions altogether.)
  def repl(target = nil)
    Pry::REPL.new(self, :target => target).start
  end

  def evaluate_ruby(code)
    inject_sticky_locals!
    exec_hook :before_eval, code, self

    result = current_binding.eval(code, Pry.eval_path, Pry.current_line)
    set_last_result(result, code)
  ensure
    update_input_history(code)
    exec_hook :after_eval, result, self
  end

  # Output the result or pass to an exception handler (if result is an exception).
  def show_result(result)
    if last_result_is_exception?
      exception_handler.call(output, result, self)
    elsif should_print?
      print.call(output, result, self)
    else
      # nothin'
    end
  rescue RescuableException => e
    # Being uber-paranoid here, given that this exception arose because we couldn't
    # serialize something in the user's program, let's not assume we can serialize
    # the exception either.
    begin
      output.puts "(pry) output error: #{e.inspect}\n#{e.backtrace.join("\n")}"
    rescue RescuableException => e
      if last_result_is_exception?
        output.puts "(pry) output error: failed to show exception"
      else
        output.puts "(pry) output error: failed to show result"
      end
    end
  ensure
    output.flush if output.respond_to?(:flush)
  end

  # Force `eval_string` into the encoding of `val`. [Issue #284]
  def ensure_correct_encoding!(val)
    if @eval_string.empty? &&
        val.respond_to?(:encoding) &&
        val.encoding != @eval_string.encoding
      @eval_string.force_encoding(val.encoding)
    end
  end
  private :ensure_correct_encoding!

  # If the given line is a valid command, process it in the context of the
  # current `eval_string` and binding.
  # @param [String] val The line to process.
  # @return [Boolean] `true` if `val` is a command, `false` otherwise
  def process_command(val)
    val = val.lstrip if /^\s\S/ !~ val
    val = val.chomp
    result = commands.process_line(val,
      :target => current_binding,
      :output => output,
      :eval_string => @eval_string,
      :pry_instance => self,
      :hooks => hooks
    )

    # set a temporary (just so we can inject the value we want into eval_string)
    Pry.current[:pry_cmd_result] = result

    # note that `result` wraps the result of command processing; if a
    # command was matched and invoked then `result.command?` returns true,
    # otherwise it returns false.
    if result.command?
      if !result.void_command?
        # the command that was invoked was non-void (had a return value) and so we make
        # the value of the current expression equal to the return value
        # of the command.
        @eval_string.replace "::Pry.current[:pry_cmd_result].retval\n"
      end
      true
    else
      false
    end
  end

  # Same as process_command, but outputs exceptions to `#output` instead of
  # raising.
  # @param [String] val  The line to process.
  # @return [Boolean] `true` if `val` is a command, `false` otherwise
  def process_command_safely(val)
    process_command(val)
  rescue CommandError, Pry::Slop::InvalidOptionError, MethodSource::SourceNotFoundError => e
    Pry.last_internal_error = e
    output.puts "Error: #{e.message}"
    true
  end

  # Run the specified command.
  # @param [String] val The command (and its params) to execute.
  # @return [Pry::Command::VOID_VALUE]
  # @example
  #   pry_instance.run_command("ls -m")
  def run_command(val)
    commands.process_line(val,
      :eval_string => @eval_string,
      :target => current_binding,
      :pry_instance => self,
      :output => output
    )
    Pry::Command::VOID_VALUE
  end

  # Execute the specified hook.
  # @param [Symbol] name The hook name to execute
  # @param [*Object] args The arguments to pass to the hook
  # @return [Object, Exception] The return value of the hook or the exception raised
  #
  # If executing a hook raises an exception, we log that and then continue sucessfully.
  # To debug such errors, use the global variable $pry_hook_error, which is set as a
  # result.
  def exec_hook(name, *args, &block)
    e_before = hooks.errors.size
    hooks.exec_hook(name, *args, &block).tap do
      hooks.errors[e_before..-1].each do |e|
        output.puts "#{name} hook failed: #{e.class}: #{e.message}"
        output.puts "#{e.backtrace.first}"
        output.puts "(see _pry_.hooks.errors to debug)"
      end
    end
  end

  # Set the last result of an eval.
  # This method should not need to be invoked directly.
  # @param [Object] result The result.
  # @param [String] code The code that was run.
  def set_last_result(result, code="")
    @last_result_is_exception = false
    @output_array << result

    self.last_result = result unless code =~ /\A\s*\z/
  end

  #
  # Set the last exception for a session.
  #
  # @param [Exception] e
  #   the last exception.
  #
  def last_exception=(e)
    last_exception = Pry::LastException.new(e)
    @last_result_is_exception = true
    @output_array << last_exception
    @last_exception = last_exception
  end

  # Update Pry's internal state after evalling code.
  # This method should not need to be invoked directly.
  # @param [String] code The code we just eval'd
  def update_input_history(code)
    # Always push to the @input_array as the @output_array is always pushed to.
    @input_array << code
    if code
      Pry.line_buffer.push(*code.each_line)
      Pry.current_line += code.lines.count
    end
  end

  # @return [Boolean] True if the last result is an exception that was raised,
  #   as opposed to simply an instance of Exception (like the result of
  #   Exception.new)
  def last_result_is_exception?
    @last_result_is_exception
  end

  # Whether the print proc should be invoked.
  # Currently only invoked if the output is not suppressed.
  # @return [Boolean] Whether the print proc should be invoked.
  def should_print?
    !@suppress_output
  end

  # Returns the appropriate prompt to use.
  # @return [String] The prompt.
  def select_prompt
    object = current_binding.eval('self')

    open_token = @indent.open_delimiters.any? ? @indent.open_delimiters.last :
      @indent.stack.last

    c = Pry::Config.from_hash({
                       :object         => object,
                       :nesting_level  => binding_stack.size - 1,
                       :open_token     => open_token,
                       :session_line   => Pry.history.session_line_count + 1,
                       :history_line   => Pry.history.history_line_count + 1,
                       :expr_number    => input_array.count,
                       :_pry_          => self,
                       :binding_stack  => binding_stack,
                       :input_array    => input_array,
                       :eval_string    => @eval_string,
                       :cont           => !@eval_string.empty?})

    Pry.critical_section do
      # If input buffer is empty then use normal prompt
      if eval_string.empty?
        generate_prompt(Array(prompt).first, c)

      # Otherwise use the wait prompt (indicating multi-line expression)
      else
        generate_prompt(Array(prompt).last, c)
      end
    end
  end

  def generate_prompt(prompt_proc, conf)
    if prompt_proc.arity == 1
      prompt_proc.call(conf)
    else
      prompt_proc.call(conf.object, conf.nesting_level, conf._pry_)
    end
  end
  private :generate_prompt

  # the array that the prompt stack is stored in
  def prompt_stack
    @prompt_stack ||= Array.new
  end
  private :prompt_stack

  # Pushes the current prompt onto a stack that it can be restored from later.
  # Use this if you wish to temporarily change the prompt.
  # @param [Array<Proc>] new_prompt
  # @return [Array<Proc>] new_prompt
  # @example
  #    new_prompt = [ proc { '>' }, proc { '>>' } ]
  #    push_prompt(new_prompt) # => new_prompt
  def push_prompt(new_prompt)
    prompt_stack.push new_prompt
  end

  # Pops the current prompt off of the prompt stack.
  # If the prompt you are popping is the last prompt, it will not be popped.
  # Use this to restore the previous prompt.
  # @return [Array<Proc>] Prompt being popped.
  # @example
  #    prompt1 = [ proc { '>' }, proc { '>>' } ]
  #    prompt2 = [ proc { '$' }, proc { '>' } ]
  #    pry = Pry.new :prompt => prompt1
  #    pry.push_prompt(prompt2)
  #    pry.pop_prompt # => prompt2
  #    pry.pop_prompt # => prompt1
  #    pry.pop_prompt # => prompt1
  def pop_prompt
    prompt_stack.size > 1 ? prompt_stack.pop : prompt
  end

  undef :pager if method_defined? :pager
  # Returns the currently configured pager
  # @example
  #   _pry_.pager.page text
  def pager
    Pry::Pager.new(self)
  end

  undef :output if method_defined? :output
  # Returns an output device
  # @example
  #   _pry_.output.puts "ohai!"
  def output
    Pry::Output.new(self)
  end

  # Raise an exception out of Pry.
  #
  # See Kernel#raise for documentation of parameters.
  # See rb_make_exception for the inbuilt implementation.
  #
  # This is necessary so that the raise-up command can tell the
  # difference between an exception the user has decided to raise,
  # and a mistake in specifying that exception.
  #
  # (i.e. raise-up RunThymeError.new should not be the same as
  #  raise-up NameError, "unititialized constant RunThymeError")
  #
  def raise_up_common(force, *args)
    exception = if args == []
                  last_exception || RuntimeError.new
                elsif args.length == 1 && args.first.is_a?(String)
                  RuntimeError.new(args.first)
                elsif args.length > 3
                  raise ArgumentError, "wrong number of arguments"
                elsif !args.first.respond_to?(:exception)
                  raise TypeError, "exception class/object expected"
                elsif args.length === 1
                  args.first.exception
                else
                  args.first.exception(args[1])
                end

    raise TypeError, "exception object expected" unless exception.is_a? Exception

    exception.set_backtrace(args.length === 3 ? args[2] : caller(1))

    if force || binding_stack.one?
      binding_stack.clear
      throw :raise_up, exception
    else
      binding_stack.pop
      raise exception
    end
  end
  def raise_up(*args); raise_up_common(false, *args); end
  def raise_up!(*args); raise_up_common(true, *args); end

  # Convenience accessor for the `quiet` config key.
  # @return [Boolean]
  def quiet?
    config.quiet
  end
end
