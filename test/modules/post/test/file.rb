lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

# load 'test/lib/module_test.rb'
# load 'lib/rex/text.rb'
# load 'lib/msf/core/post/file.rb'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::ModuleTest::PostTestFileSystem
  include Msf::Post::Common
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Testing Remote File Manipulation',
        'Description' => %q{ This module will test Post::File API methods },
        'License' => MSF_LICENSE,
        'Author' => [ 'egypt' ],
        'Platform' => [ 'windows', 'linux', 'unix', 'java', 'osx' ],
        'SessionTypes' => [ 'meterpreter', 'shell', 'powershell' ]
      )
    )
  end

  #
  # Change directory into a place that we have write access.
  #
  # The +cleanup+ method will change it back
  #
  def setup
    push_test_directory
    super
  end

  def cleanup
    pop_test_directory
    super
  end

  def test_dir
    fs_sep = session.platform == 'windows' ? '\\' : '/'

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

    it 'should create directories' do
      mkdir(datastore['BaseDirectoryName'])
      ret = directory?(datastore['BaseDirectoryName'])
      ret &&= write_file([datastore['BaseDirectoryName'], 'file'].join(fs_sep), '')
      ret &&= mkdir([datastore['BaseDirectoryName'], 'directory'].join(fs_sep))
      ret &&= write_file([datastore['BaseDirectoryName'], 'directory', 'file'].join(fs_sep), '')
      ret
    end

    it 'should list the directory we just made' do
      dents = dir(datastore['BaseDirectoryName'])
      dents.include?('file') && dents.include?('directory')
    end

    it 'should recursively delete the directory we just made' do
      rm_rf(datastore['BaseDirectoryName'])
      !directory?(datastore['BaseDirectoryName'])
    end

    unless (session.platform == 'windows') || (session.platform != 'windows' && command_exists?('ln'))
      print_warning('skipping link related checks because the target is incompatible')
    else
      it 'should delete a symbolic link target' do
        mkdir(datastore['BaseDirectoryName'])
        ret = directory?(datastore['BaseDirectoryName'])
        link = "#{datastore['BaseDirectoryName']}.lnk"
        ret &&= write_file([datastore['BaseDirectoryName'], 'file'].join(fs_sep), '')
        make_symlink(datastore['BaseDirectoryName'], link)
        unless exists?(link)
          print_error('failed to create the symbolic link')
        end
        rm_rf(link)
        # the link should have been deleted
        ret &&= !exists?(link)
        # but the target directory and its contents should still be intact
        ret &&= exists?("#{[datastore['BaseDirectoryName'], 'file'].join(fs_sep)}")
        rm_rf(datastore['BaseDirectoryName'])
        ret
      end

      it 'should not recurse into symbolic link directories' do
        mkdir(datastore['BaseDirectoryName'] + '.1')
        mkdir(datastore['BaseDirectoryName'] + '.2')
        ret = directory?(datastore['BaseDirectoryName'] + '.1') && directory?(datastore['BaseDirectoryName'] + '.2')
        ret &&= write_file([datastore['BaseDirectoryName'] + '.1', 'file'].join(fs_sep), '')
        # make a symlink in dir.2 to dir.1 to ensure the deletion does not recurse into dir.1
        make_symlink("#{datastore['BaseDirectoryName']}.1", "#{datastore['BaseDirectoryName']}.2/link")
        rm_rf("#{datastore['BaseDirectoryName']}.2")
        # check that dir.1's contests are still intact
        ret &&= exists?([datastore['BaseDirectoryName'] + '.1', 'file'].join(fs_sep))
        rm_rf("#{datastore['BaseDirectoryName']}.1")
        ret
      end
    end
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
        '%WINDIR%\\system32\\calc.exe',
        File.expand_path(__FILE__)
      ].each do |path|
        ret = true if file?(path)
      end

      ret
    end

    it 'should create text files' do
      rm_f(datastore['BaseFileName'])
      ret = write_file(datastore['BaseFileName'], 'foo')
      ret &&= file?(datastore['BaseFileName'])
      ret
    end

    it 'should read the text we just wrote' do
      f = read_file(datastore['BaseFileName'])
      ret = (f == 'foo')
      unless ret
        vprint_status("Didn't read what we wrote, actual file on target: |#{f.inspect}| - #{f.bytes.inspect}")
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
        vprint_status("Didn't read what we wrote, actual file on target: |#{file_contents.inspect}| - #{file_contents.bytes.inspect}")
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
    # binary_data = ::File.read('/bin/echo')
    # binary_data = "\xff\x00\xff\xfe\xff\`$(echo blha)\`"
    binary_data = ((0..255).to_a * 500).shuffle.pack("c*")
    it 'should write binary data' do
      vprint_status "Writing #{binary_data.length} bytes"
      t = Time.now
      ret = write_file(datastore['BaseFileName'], binary_data)
      vprint_status("Finished in #{Time.now - t}")

      ret &&= file_exist?(datastore['BaseFileName'])
      ret
    end

    it 'should read the binary data we just wrote' do
      bin = read_file(datastore['BaseFileName'])
      vprint_status "Read #{bin.length} bytes" if bin

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

      test_string = "\xde\xad\xbe\xef"

      vprint_status "expected: #{test_string.bytes} - #{test_string.encoding}"
      vprint_status "actual: #{bin.bytes} - #{bin.encoding}"

      bin == test_string
    end
  end

  def test_path_expansion_nix
    unless session.platform =~ /win/i
      it 'should expand home' do
        home1 = expand_path('~')
        home2 = expand_path('$HOME')
        home1 == home2 && home1.length > 0
      end

      it 'should not expand non-isolated tilde' do
        s = '~a'
        result = expand_path(s)
        s == result
      end

      it 'should not expand mid-string tilde' do
        s = '/home/~'
        result = expand_path(s)
        s == result
      end

      it 'should not expand env vars with invalid naming' do
        s = 'no environment $ variables /here'
        result = expand_path(s)
        s == result
      end

      it 'should expand multiple variables' do
        result = expand_path('/blah/$HOME/test/$USER')
        home = expand_path('$HOME')
        user = expand_path('$USER')
        expected = "/blah/#{home}/test/#{user}"
        result == expected
      end
    end
  end

  def make_symlink(target, symlink)
    if session.platform == 'windows'
      cmd_exec("cmd.exe", "/c mklink #{directory?(target) ? '/D ' : ''}#{symlink} #{target}")
    else
      cmd_exec("ln -s $(pwd)/#{target} $(pwd)/#{symlink}")
    end
  end

  def register_dir_for_cleanup(path)
  end

end
