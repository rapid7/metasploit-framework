#
# This class is responsible for handling Readline/Reline-agnostic user input.
#
class Msf::Ui::Console::MsfReadline
  require 'singleton'
  # Required to check the Reline flag.
  require 'msf/core/feature_manager'
  require 'readline'
  require 'reline'

  include Singleton

  attr_reader :history

  def initialize
    @backend = using_reline? ? ::Reline : ::Readline
    @history = @backend::HISTORY
  end

  def method_missing(sym, *args, &block)
    if @backend.respond_to?(sym)
      @backend.send(sym, *args, &block)
    else
      msg = "Method '#{sym}' not found in #{@backend.class}"
      elog(msg)
      raise NoMethodError, msg
    end
  end

  # IRB changes propagate out of the context of IRB. We store the current state and restore it on exit.
  # TODO: Once IRB fixes this behaviour, we should be able to remove this patch.
  def cache_current_config
    @current_config = {}
    @current_config[:autocompletion] = self.autocompletion
    @current_config[:core] = @backend.core.dup if using_reline?
  end

  def restore_cached_config
    self.autocompletion = @current_config[:autocompletion]
    @backend.instance_variable_set(:@core, @current_config[:core]) if using_reline?
  end

  # Read a line from the user, and return it.
  # @param prompt [String] The prompt to show to the user.
  # @param add_history [Boolean] True if the user's input should be saved to the history.
  # @param opts [Hash] Options
  # @return String The line that the user has entered.
  def readline(prompt, add_history = false, opts: {})
    input(prompt, add_history, opts: opts)
  end

  def using_reline?
    return @using_reline unless @using_reline.nil?

    @using_reline = Msf::FeatureManager.instance.enabled?(Msf::FeatureManager::USE_RELINE)
  end

  private

  attr_accessor :using_reline, :backend, :current_config

  def input(*args, opts: {})
    using_reline? ? input_reline(*args, opts: opts) : input_rbreadline(*args, opts: opts)
  end

  def input_rbreadline(prompt, add_history = false, opts: {})
    # rb-readlines's Readline.readline hardcodes the input and output to
    # $stdin and $stdout, which means setting `Readline.input` or
    # `Readline.output` has no effect when running `Readline.readline` with
    # rb-readline, so need to reimplement
    # []`Readline.readline`](https://github.com/luislavena/rb-readline/blob/ce4908dae45dbcae90a6e42e3710b8c3a1f2cd64/lib/readline.rb#L36-L58)
    # for rb-readline to support setting input and output.  Output needs to
    # be set so that colorization works for the prompt on Windows.

    input_on_entry = RbReadline.rl_instream
    output_on_entry = RbReadline.rl_outstream

    begin
      RbReadline.rl_instream = opts[:fd]
      RbReadline.rl_outstream = opts[:output]
      line = RbReadline.readline(prompt.to_s)
    rescue ::StandardError => e
      RbReadline.rl_instream = input_on_entry
      RbReadline.rl_outstream = output_on_entry
      RbReadline.rl_cleanup_after_signal
      RbReadline.rl_deprep_terminal

      raise e
    end

    if add_history && line && !line.start_with?(' ')
      # Don't add duplicate lines to history
      if ::Readline::HISTORY.empty? || line.strip != ::Readline::HISTORY[-1]
        RbReadline.add_history(line.strip)
      end
    end

    line.dup
  end

  def input_reline(prompt, add_history = false, opts: {})
    input_on_entry = Reline::IOGate.instance_variable_get(:@input)
    output_on_entry = Reline::IOGate.instance_variable_get(:@output)

    begin
      # TODO: Currently we can't pase in non-ASCII chars. The code below fixes that but breaks out rab completion due
      # to encoding issues.
      # input_external_encoding = opts[:fd].external_encoding
      # input_internal_encoding = opts[:fd].internal_encoding
      # opts[:fd].set_encoding(::Encoding::UTF_8)
      Reline.input = opts[:fd]
      Reline.output = opts[:output]
      line = Reline.readline(prompt.to_s, add_history)
    ensure
      # opts[:fd].set_encoding(input_external_encoding, input_internal_encoding)
      Reline.input = input_on_entry
      Reline.output = output_on_entry
    end

    # Don't add duplicate lines to history
    if Reline::HISTORY.length > 1 && line == Reline::HISTORY[-2]
      Reline::HISTORY.pop
    end

    line.dup
  end
end
