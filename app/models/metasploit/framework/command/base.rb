# @abstract Subclass and define `#run_with_valid` to run when the subclass instance is valid and {#run} is called.  If
#   there are recursive validation errors, {#print_validation_errors} should be overriden and `super` called to print
#   the errors directly on the subclass instance.
#
# A command used in `msfconsole`.
class Metasploit::Framework::Command::Base < Metasploit::Model::Base
  include Metasploit::Framework::Command::TabCompletion

  #
  # Attributes
  #

  # @!attribute [rw] dispatcher
  #   Command dispatcher
  #
  #   @return [Msf::Ui::Console::CommandDispatcher]
  attr_accessor :dispatcher

  # @!attribute [rw] words
  #   Words parsed from console.
  #
  #   @return [Array<String>]
  attr_writer :words

  #
  #
  # Validations
  #
  #

  #
  # Method Validations
  #

  validate :words_parsable

  #
  # Attribute Validations
  #

  validates :dispatcher,
            presence: true

  #
  # Methods
  #

  class << self
    # The name of this command as called from the {#dispatcher}.
    #
    # @return [String]
    def command_name
      name.demodulize.underscore
    end

    attr_accessor :description

    # Declares {#words} parsing routine.
    #
    # @yield [parsable_words] Body of #parse_words method specific to this class.
    # @yieldparam parsable_words [Array<String>] A duplicate of {#words} that can be safely modified by
    #   `OptionParser#parse!` without changing {#words}.
    def parse_words(&block)
      @parse_words_block = block
    end

    attr_writer :parse_words_block

    def parse_words_block
      @parse_words_block ||= ->(parsable_words){}
    end
  end

  # @!method print_line(message=nil)
  #   Print `messages` followed by a new line.
  #
  #   @return [void]
  #
  # @!method print_error(message=nil)
  #   Print message as an error (prefixed by red '[-]') followed by a new line.
  #
  #   @return [void]
  #
  # @!method width
  #    The width of the TTY attached to the {#dispatcher}'s output.
  #
  #    @return [80] if the output is not a TTY.
  #    @return [Integer] otherwise.
  delegate :print_error,
           :print_good,
           :print_line,
           :print_status,
           :print_warning,
           :width,
           to: :dispatcher

  # Runs the command.  Command is automatically validated.  If it is valid, then {#run_with_valid} will be called,
  # otherwise, if the command is invalid, {#print_validation_errors} is called.
  #
  # @return [void]
  def run
    if valid?
      run_with_valid
    else
      print_validation_errors
    end
  end

  # Words from console that are passed to this command.
  #
  # @return [Array<String>] [] by default
  def words
    @words ||= []
  end

  protected

  # @note `valid?` should be called before using this method to populate `errors`.
  #
  # Prints full error messages directly on this command.
  #
  # @return [void]
  def print_validation_errors
    errors.full_messages.each do |full_message|
      print_error full_message
    end
  end

  private

  # Parses {#words} using {parse_words_block}.  `OptionParser::ParseError` are stored to `@parse_error` and converted to
  # a validation error by {#words_parsable}.
  #
  # @return [void]
  def parse_words
    unless @words_parsed
      # have to dup because OptionParse#parse! will modify the Array.
      parsable_words = words.dup

      begin
        instance_exec(parsable_words, &self.class.parse_words_block)
      rescue OptionParser::ParseError => error
        @parse_error = error
      end

      @words_parsed = true
    end
  end

  def words_parsable
    parse_words

    if @parse_error
      errors[:words] << @parse_error.to_s
    end
  end
end