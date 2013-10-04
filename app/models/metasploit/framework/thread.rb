# The metadata for a thread used in {Metasploit::Framework::Thread::Manager}
class Metasploit::Framework::Thread < Metasploit::Model::Base
  #
  # Attributes
  #

  # @!attribute [rw] backtrace
  #   The backtrace when this thread was spawned.
  #
  #   @return [Array<String>]
  attr_accessor :backtrace

  # @!attribute [rw] block
  #   Block to call in {#run}.
  #
  #   @return [Proc]
  attr_accessor :block

  # @!attribute [rw] block_arguments
  #   Arguments passed to {#block} in {#run}.
  #
  #   @return [Array, nil]
  attr_accessor :block_arguments

  # @!attribute [rw] critical
  #   Whether this thread is critical and should not be killed by certain bulk Thread culling commands in the framework.
  #
  #   @return [Boolean]
  attr_accessor :critical

  # @!attribute [rw] name
  #   The name of this thread.  Used to kill ruby `Thread` spawned to {#run} this thread.
  #
  #   @return [String]
  attr_accessor :name

  # @!attribute [rw] spawned_at
  #   When this thread was spawned as a ruby `Thread` by a {Metasploit::Framework::Thread::Manager}.
  #
  #   @return [Time]
  attr_accessor :spawned_at

  #
  # Validations
  #

  validates :backtrace,
            presence: true
  validates :block,
            presence: true
  validates :critical,
            inclusion: {
                in: [
                    false,
                    true
                ]
            }
  validates :name,
            presence: true
  validates :spawned_at,
            presence: true

  #
  # Methods
  #

  def initialize(attributes={}, &block)
    super(attributes)

    if block
      if self.block
        raise ArgumentError,
              ":block attribute and &block cannot both be present"
      else
        self.block = block
      end
    end
  end

  # Logs the `error` along with context from this thread and then raises the `error`.
  def log_and_raise(error)
    log = format_error_log_message(error)
    elog(log)

    raise error
  end

  # Runs {#block} with {#block_arguments}.
  def run
    block.call(*block_arguments)
  end

  private

  def format_error_log_message(error)
    lines = []
    lines << ''
    lines << 'Thread:'
    lines << "  Name: #{name}"
    lines << "  Critical: #{critical}"
    lines << "  Backtrace:"

    backtrace.each do |line|
      lines << "    #{line}"
    end

    if error
      lines << "  Error:"
      lines << "    Class: #{error.class}"
      lines << "    Message: #{error}"

      error_backtrace = error.backtrace

      if error_backtrace
        lines << "    Backtrace:"

        error_backtrace.each do |line|
          lines << "      #{line}"
        end
      end
    end

    formatted = lines.join("\n")

    formatted
  end
end
