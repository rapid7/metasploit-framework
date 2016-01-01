class Metasploit::Framework::Command::Console::Driver
  include Celluloid

  # @param options (see Metasploit::Framework::Command::Console#driver_options)
  # @option (see Metasploit::Framework::Command::Console#driver_options)
  # @return [void]
  def run(options={})
    driver(options).run
  end

  private

  # The console UI driver.
  #
  # @return [Msf::Ui::Console::Driver]
  def driver(options)
    # require here so minimum loading is done before {start} is called.
    require 'msf/ui'

    Msf::Ui::Console::Driver.new(
        Msf::Ui::Console::Driver::DefaultPrompt,
        Msf::Ui::Console::Driver::DefaultPromptChar,
        options
    )
  end
end