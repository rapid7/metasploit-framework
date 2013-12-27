class Metasploit::Framework::Command::Check::Help < Metasploit::Framework::Command::Base
  include Metasploit::Framework::Command::Child

  protected

  def run_with_valid
    print option_parser.help
    print_line
    print_line "Check to see if target is vulnerable to #{dispatcher.metasploit_instance.full_name}"
  end
end