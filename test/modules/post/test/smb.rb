require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex'
require 'fileutils'

lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::ModuleTest::PostTestFileSystem

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Testing SMB sessions work',
        'Description' => %q{ This module will test the SMB sessions work },
        'License' => MSF_LICENSE,
        'Author' => [ 'sjanusz-r7'],
        'Platform' => all_platforms,
        'SessionTypes' => [ 'smb' ]
      )
    )
  end

  def test_console_help
    it 'should support the help command' do
      stdout = with_mocked_console(session) { |console| console.run_single('help') }
      ret = true
      ret &&= stdout.buf.include?('Core Commands')
      ret &&= stdout.buf.include?('Shares Commands')
      ret &&= stdout.buf.include?('Local File System Commands')
      ret
    end
  end

  def test_upload_and_download
    readonly_share = 'readonly'
    modifiable_share = 'modifiable'

    Tempfile.create do |temp_file|
      filename = File.basename(temp_file)
      full_path = temp_file.to_path

      it 'should support uploading files' do
        stdout = with_mocked_console(session) do |console|
          console.run_single("shares -i #{modifiable_share}")
          console.run_single("upload #{full_path} #{filename}")
        end

        ret = true
        # Or filename?
        ret &&= stdout.buf.include?("#{full_path} uploaded to #{filename}")
        ret
      end

      it 'should not upload to readonly share' do
        stdout = with_mocked_console(session) do |console|
          console.run_single("shares -i #{readonly_share}")
          console.run_single("upload #{full_path} #{filename}")
        end

        ret = true
        ret &&= stdout.buf.include?('Error running command upload')
        ret &&= stdout.buf.include?('The server responded with an unexpected status code: STATUS_ACCESS_DENIED')
        ret
      end

      it 'should support deleting files' do
        stdout = with_mocked_console(session) do |console|
          console.run_single("shares -i #{modifiable_share}")
          console.run_single("delete #{filename}")
        end

        ret = true
        ret &&= stdout.buf.include?("Deleted #{filename}")
        ret
      end
    end

    Tempfile.create do |temp_file|
      remote_filename = 'hello_world.txt'
      remote_dir = 'text_files'
      full_path = temp_file.to_path

      it 'should support downloading files' do
        stdout = with_mocked_console(session) do |console|
          console.run_single("shares -i #{modifiable_share}")
          console.run_single("cd #{remote_dir}")
          console.run_single("download #{remote_filename} #{full_path}")
        end

        ret = true
        ret &&= stdout.buf.include?("Downloaded #{remote_dir}\\#{remote_filename} to #{full_path}")
        ret
      end
    end
  end

  def test_files
    modifiable_share = 'modifiable'

    it 'should output files in the current directory' do
      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{modifiable_share}")
        console.run_single('ls')
      end

      ret = true
      ret &&= stdout.buf.include?('recursive')
      ret &&= stdout.buf.include?('text_files')
      ret
    end
  end

  def test_directories
    it 'should support changing a directory' do
      folder_name = 'text_files'
      modifiable_share = 'modifiable'
      expected_file_name = 'hello_world.txt'

      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{modifiable_share}")
        console.run_single("cd #{folder_name}")
        console.run_single('ls')
      end

      ret = true
      ret &&= stdout.buf.include? expected_file_name
      ret
    end

    it 'should support creating a new directory' do
      modifiable_share = 'modifiable'
      new_directory_name = 'my_new_directory'

      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{modifiable_share}")
        console.run_single("mkdir #{new_directory_name}")
      end

      ret = true
      ret &&= stdout.buf.include?("Directory #{new_directory_name} created")
      ret
    end

    it 'should support deleting a directory' do
      modifiable_share = 'modifiable'
      new_directory_name = 'my_new_directory'

      stdout = with_mocked_console(session) do |console|
        console.run_single("shares -i #{modifiable_share}")
        console.run_single("rmdir #{new_directory_name}")
      end

      ret = true
      ret &&= stdout.buf.include?("Deleted #{new_directory_name}")
      ret
    end
  end

  def test_shares
    it 'should support switching shares' do
      stdout = with_mocked_console(session) { |console| console.run_single('shares -i 0') }
      ret = true
      ret &&= stdout.buf.include?('Successfully connected to modifiable')

      stdout = with_mocked_console(session) { |console| console.run_single('shares -i 1') }

      ret &&= stdout.buf.include?('Successfully connected to readonly')

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
