class Metasploit::Framework::Command::Use < Metasploit::Framework::Command::Base
  include Metasploit::Framework::Command::Parent

  self.description = 'Selects a module by name'

  #
  # Subcommands
  #

  subcommand :help
  subcommand :set_metasploit_instance, default: true

  #
  # Methods
  #

  def option_parser
    @option_parser ||= OptionParser.new { |option_parser|
      option_parser.banner = "Usage: #{self.class.command_name} (-h|--help|MODULE_FULL_NAME)"

      option_parser.on_tail('-h', '--help', 'Show this help') do
        self.subcommand_name = :help
      end
    }
  end

  private

  parse_words do |parsable_words|
    positional_arguments = option_parser.parse!(parsable_words)
    # user may accidentally specify multiple Module::Class#full_names.  Allow validation to catch this without
    # messing up {Metasploit::Framework::Command::Use::ActivateModule#module_class_full_name}.
    subcommand_by_name[:set_metasploit_instance].module_class_full_name = positional_arguments.first
  end
end
