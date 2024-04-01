require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex'

lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::ModuleTest::PostTestFileSystem

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Testing MSSQL sessions work',
        'Description' => %q{ This module will test the mssql sessions work },
        'License' => MSF_LICENSE,
        'Author' => [ 'zachgoldman'],
        'Platform' => all_platforms,
        'SessionTypes' => [ 'mssql' ]
      )
    )
  end

  def setup
    super
  end

  def cleanup
    super
  end

  def test_console_query
    it "should return a version" do
      stdout = with_mocked_console(session) { |console| console.run_single("query 'select @@version;'") }
      ret = true
      ret &&= stdout.buf.match?(/Microsoft SQL Server \d+.\d+/)
      ret
    end
  end

  def test_console_help
    it "should support the help command" do
      stdout = with_mocked_console(session) { |console| console.run_single("help") }
      ret = true
      ret &&= stdout.buf.include?('Core Commands')
      ret &&= stdout.buf.include?('MSSQL Client Commands')
      ret
    end
  end

  private

  def all_platforms
    Msf::Module::Platform.subclasses.collect { |c| c.realname.downcase }
  end

  # Wrap the console with a mocked stdin/stdout for testing purposes. This ensures the console
  # will not write the real stdout, and the contents can be verified in the test
  # @param [Session] session
  # @return [Rex::Ui::Text::Output::Buffer] the stdout buffer
  def with_mocked_console(session)
    old_input = session.console.input
    old_output = session.console.output

    mock_input = Rex::Ui::Text::Input.new
    mock_output = Rex::Ui::Text::Output::Buffer.new

    session.console.init_ui(mock_input, mock_output)
    yield session.console

    mock_output
  ensure
    session.console.init_ui(old_input, old_output)
  end
end
