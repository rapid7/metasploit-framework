lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

# load 'test/lib/module_test.rb'
# load 'lib/rex/text.rb'
# load 'lib/msf/core/post/file.rb'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::Post::Common
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Testing Remote File Manipulation',
        'Description' => %q{ This module will test Post::File API methods },
        'License' => MSF_LICENSE,
        'Author' => [ 'egypt'],
        'Platform' => [ 'windows', 'linux', 'java' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
    )

    register_options(
      [
        OptString.new('BaseFileName', [true, 'File name to create', 'meterpreter-test'])
      ], self.class
    )
  end

  #
  # Change directory into a place that we have write access.
  #
  # The +cleanup+ method will change it back
  #
  def setup
    @old_pwd = pwd
    tmp = directory?('/tmp') ? '/tmp' : '%TEMP%'
    vprint_status("Setup: changing working directory to #{tmp}")
    cd(tmp)

    super
  end

  def test_file
    it 'should test for file existence' do
      ret = false
      [
        'c:\\boot.ini',
        'c:\\pagefile.sys',
        '/etc/passwd',
        '/etc/master.passwd',
        '%WINDIR%\\system32\\notepad.exe',
        '%WINDIR%\\system32\\calc.exe'
      ].each do |path|
        ret = true if file?(path)
      end

      ret
    end

    it 'should test for directory existence' do
      ret = false
      [
        'c:\\',
        '/etc/',
        '/tmp'
      ].each do |path|
        ret = true if directory?(path)
      end

      ret
    end

    it 'should create text files' do
      rm_f(datastore['BaseFileName'])
      write_file(datastore['BaseFileName'], 'foo')

      file?(datastore['BaseFileName'])
    end

    it 'should read the text we just wrote' do
      f = read_file(datastore['BaseFileName'])
      ret = (f == 'foo')
      unless ret
        print_error("Didn't read what we wrote, actual file on target: |#{f}|")
      end

      ret
    end

    it 'should append text files' do
      ret = true
      append_file(datastore['BaseFileName'], 'bar')

      ret &&= read_file(datastore['BaseFileName']) == 'foobar'
      append_file(datastore['BaseFileName'], 'baz')
      final_contents = read_file(datastore['BaseFileName'])
      ret &&= final_contents == 'foobarbaz'
      unless ret
        print_error("Didn't read what we wrote, actual file on target: #{final_contents}")
      end

      ret
    end

    it 'should delete text files' do
      rm_f(datastore['BaseFileName'])

      !file_exist?(datastore['BaseFileName'])
    end

    it 'should move files' do
      # Make sure we don't have leftovers from a previous run
      moved_file = datastore['BaseFileName'] + '-moved'
      begin
        rm _f(datastore['BaseFileName'])
      rescue StandardError
        nil
      end
      begin
        rm_f(moved_file)
      rescue StandardError
        nil
      end

      # touch a new file
      write_file(datastore['BaseFileName'], '')

      rename_file(datastore['BaseFileName'], moved_file)
      res &&= exist?(moved_file)
      res &&= !exist?(datastore['BaseFileName'])

      # clean up
      begin
        rm_f(datastore['BaseFileName'])
      rescue StandardError
        nil
      end
      begin
        rm_f(moved_file)
      rescue StandardError
        nil
      end
    end
  end

  def test_binary_files
    # binary_data = ::File.read("/bin/ls")
    binary_data = ::File.read('/bin/echo')
    # binary_data = "\xff\x00\xff\xfe\xff\`$(echo blha)\`"
    it 'should write binary data' do
      vprint_status "Writing #{binary_data.length} bytes"
      t = Time.now
      write_file(datastore['BaseFileName'], binary_data)
      vprint_status("Finished in #{Time.now - t}")

      file_exist?(datastore['BaseFileName'])
    end

    it 'should read the binary data we just wrote' do
      bin = read_file(datastore['BaseFileName'])
      vprint_status "Read #{bin.length} bytes"

      bin == binary_data
    end

    it 'should delete binary files' do
      rm_f(datastore['BaseFileName'])

      !file_exist?(datastore['BaseFileName'])
    end

    it 'should append binary data' do
      write_file(datastore['BaseFileName'], "\xde\xad")
      append_file(datastore['BaseFileName'], "\xbe\xef")
      bin = read_file(datastore['BaseFileName'])
      rm_f(datastore['BaseFileName'])

      bin == "\xde\xad\xbe\xef"
    end
  end

  def cleanup
    vprint_status("Cleanup: changing working directory back to #{@old_pwd}")
    cd(@old_pwd)
    super
  end

end
