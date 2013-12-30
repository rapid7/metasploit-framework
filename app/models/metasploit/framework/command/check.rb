# Checks if a remote host(s) is vulnerable to an exploit
class Metasploit::Framework::Command::Check < Metasploit::Framework::Command::Base
  include Metasploit::Framework::Command::Parent

  self.description = 'Check to see if a target is vulnerable'

  #
  # Subcommands
  #

  subcommand :help
  subcommand :simple,
             default: true

  #
  # Methods
  #

  def option_parser
    @option_parser ||= OptionParser.new { |option_parser|
      option_parser.banner = "Usage: #{self.class.command_name} [options]"

      option_parser.on_tail('-h', '--help', 'Show this help') do
        self.subcommand_name = :help
      end
    }
  end

  private

  parse_words do |parsable_words|
    option_parser.parse!(parsable_words)
  end
end