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

  def test_datatypes
    [
      {query: "select cast('1990-01-02' as datetime);", expected: [[DateTime.new(1990, 1, 2)]]},
      {query: "select cast(null as datetime);", expected: [[nil]]},
      {query: "select cast('1990-01-02' as smalldatetime);", expected: [[DateTime.new(1990, 1, 2)]]},
      {query: "select cast(null as smalldatetime);", expected: [[nil]]},
      {query: "select cast('19900' as float);", expected: [[19900.0]]},
      {query: "select cast(null as float);", expected: [[nil]]},
      {query: "select cast('19900' as real);", expected: [[19900.0]]},
      {query: "select cast(null as real);", expected: [[nil]]},
      {query: "select cast('12.50' as money);", expected: [[12.5]]},
      {query: "select cast(null as money);", expected: [[nil]]},
      {query: "select cast('12.50' as smallmoney);", expected: [[12.5]]},
      {query: "select cast(null as smallmoney);", expected: [[nil]]},
      {query: "select cast('1999999900' as numeric(16, 6));", expected: [[1999999900.0]]},
      {query: "select cast(null as numeric(16, 6));", expected: [[nil]]},
      {query: "select cast('foo' as ntext);", expected: [['foo']]},
      {query: "select cast(null as ntext);", expected: [[nil]]},
      {query: "select cast('bar' as varchar(10));", expected: [['bar']]},
      {query: "select cast(null as varchar(10));", expected: [[nil]]},
      {query: "select cast('baz' as nvarchar(10));", expected: [['baz']]},
      {query: "select cast(null as nvarchar(10));", expected: [[nil]]},
      {query: "select cast(42 as int);", expected: [[42]]},
      {query: "select cast(null as int);", expected: [[nil]]},
      {query: "select cast(1 as tinyint);", expected: [[1]]},
      {query: "select cast(256 as smallint);", expected: [[256]]},
      {query: "select cast(null as smallint);", expected: [[nil]]},
      {query: "select cast(1 as bit);", expected: [[1]]},
      {query: "select cast(0 as bit);", expected: [[0]]},
      {query: "select cast(null as bit);", expected: [[nil]]},
      {query: "select cast(1 as bigint);", expected: [[1]]},
      {query: "select cast(null as bigint);", expected: [[nil]]},
      {query: "select cast(0x4142 as varbinary(10));", expected: [["4142"]]},
      {query: "select cast(null as varbinary(10));", expected: [[nil]]},
      {query: "select cast('A1B2C3D4-E5F6-A7B8-C9D0-E1F2A3B4C5D6' as uniqueidentifier);", expected: [["{a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6}"]]},
      {query: "select cast(null as uniqueidentifier);", expected: [[nil]]},
      {query: "select cast(1 as int) as col union select cast(2 as int) order by col;", expected: [[1], [2]]},
    ].each do |test|
      it "should execute the query #{test[:query]} and return #{test[:expected].inspect}" do
        console = session.console
        result = console.client.query(test[:query])
        ret = result[:rows] == test[:expected]
        ret &&= result[:errors].empty?
        unless ret
          print_error("Expected: #{test[:expected].inspect}")
          print_error("Got rows: #{result[:rows].inspect}")
          print_error("Errors: #{result[:errors].inspect}") unless result[:errors].empty?
        end
        ret
      end
    end
  end

  def test_stored_procedures
    it "should handle EXEC sp_databases (NBCROW token 0xD2)" do
      result = session.console.client.query("EXEC sp_databases;")
      ret = result[:errors].empty?
      ret &&= result[:rows].any? { |row| row.include?('master') }
      ret
    end

    it "should handle EXEC sp_tables with NULLs" do
      result = session.console.client.query("EXEC sp_tables @table_type = '''TABLE''';")
      ret = result[:errors].empty?
      ret &&= result[:rows].length > 0
      ret &&= result[:rows].any? { |row| row.include?('master') && row.include?(nil) }
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
