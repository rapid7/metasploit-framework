class Metasploit::Framework::Command::Console::SupervisionGroup < Celluloid::SupervisionGroup
  supervise Metasploit::Framework::Command::Console::Spinner, as: :metasploit_framework_command_console_spinner
  supervise Metasploit::Framework::Command::Console::Driver, as: :metasploit_framework_command_console_driver
end