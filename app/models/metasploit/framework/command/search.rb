class Metasploit::Framework::Command::Search < Metasploit::Framework::Command::Base
  include Metasploit::Framework::Command::Parent

  #
  # Attributes
  #

  # @!attribute [rw] words
  #   Words parsed from console.
  #
  #   @return [Array<String>]
  attr_accessor :words

  #
  # Subcommands
  #

  subcommand :help
  subcommand :table,
             default: true

  #
  # Methods
  #

  def option_parser
    @option_parser ||= OptionParser.new { |option_parser|
      option_parser.banner = "Usage: #{self.class.name.demodulize.underscore} [options]"

      option_parser.separator ''
      option_parser.separator 'Table options:'

      option_parser.on(
          '-D',
          '--hide COLUMN',
          'Column to NOT display.',
          'Will stop default and search operators from being shown.',
          'Overrides --display.'
      ) do |column_name|
        hidden_column = Metasploit::Framework::Command::Search::Argument::Column.new(value: column_name)
        subcommand_by_name[:table].hidden_columns << hidden_column
      end

      option_parser.on(
          '-d',
          '--display COLUMN',
          'Column to display even if not a default column or one of the search operators.'
      ) do |column_name|
        displayed_column = Metasploit::Framework::Command::Search::Argument::Column.new(value: column_name)
        subcommand_by_name[:table].displayed_columns << displayed_column
      end

      option_parser.separator ''

      option_parser.on_tail('-h', '--help', 'Show this help') do
        self.subcommand_name = :help
      end
    }
  end

  private

  def parse_words
    unless @words_parsed
      # have to dup because OptionParse#parse! will modify the Array.
      parsed_words = words.dup

      begin
        # all positional arguments are table formatted operations since help doesn't take any positional arguments
        subcommand_by_name[:table].formatted_operations = option_parser.parse!(parsed_words)
      rescue OptionParser::MissingArgument
        if partial_word
          parsed_words = [*words, partial_word]
          retry
        else
          raise
        end
      end

      @words_parsed = true
    end
  end
end