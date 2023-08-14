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
        'Name' => 'Testing Meterpreter Search',
        'Description' => %q{ This module will test the meterpreter search method },
        'License' => MSF_LICENSE,
        'Author' => [ 'timwr'],
        'Platform' => [ 'windows', 'linux', 'java', 'osx' ],
        'SessionTypes' => [ 'meterpreter' ]
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

    if datastore["AddEntropy"]
      entropy_value = '-' + ('a'..'z').to_a.shuffle[0, 8].join
    else
      entropy_value = ""
    end

    @file_name = "#{datastore["BaseFileName"]}#{entropy_value}.txt"
    vprint_status("Source File Name: #{@file_name}")

    session.fs.file.rm(@file_name) rescue nil
    fd = session.fs.file.open(@file_name, "wb")
    fd.close
    super
  end

  def cleanup
    pop_test_directory
    session.fs.file.rm(@file_name) rescue nil
    super
  end

  def test_fs_search
    vprint_status("Starting search tests")

    pwd = session.fs.dir.getwd

    it "should search for new files" do
      res = true
      found = false
      files = client.fs.file.search(pwd, "*", false)
      files.each do |file|
        if file['name'] == @file_name
          res &&= (found == false)
          found = true
          res &&= (file['path'] == pwd)
        end
      end
      res &&= found
      res
    end

    it "should search recursively for files" do
      res = true
      found = false
      files = client.fs.file.search(pwd, "*", true)
      files.each do |file|
        if file['name'] == @file_name
          res &&= (found == false)
          found = true
          res &&= (file['path'] == pwd)
        end
      end
      res &&= found
      res
    end

    it "should search with globs for files" do
      res = true
      found = false
      files = client.fs.file.search(pwd, "*.txt", true)
      files.each do |file|
        if file['name'] == @file_name
          res &&= (found == false)
          found = true
          res &&= (file['path'] == pwd)
        end
      end
      res &&= found
      res
    end

    it "should search with globs ignoring files" do
      res = true
      files = client.fs.file.search(pwd, "*.ignoretxt", true)
      files.each do |file|
        res = false
      end
      res
    end
  end

  def test_fs_search_date
    vprint_status("Starting search date tests")

    pwd = session.fs.dir.getwd

    yesterday = (Time.now - 1.week).to_i
    tomorrow = (Time.now + 1.week).to_i
    it "should search with dates for files" do
      res = true
      found = false
      files = client.fs.file.search(pwd, "*", true, -1, yesterday, tomorrow)
      files.each do |file|
        if file['name'] == @file_name
          res &&= (found == false)
          res &&= (file['path'] == pwd)
          res &&= (file['mtime'] > yesterday)
          res &&= (file['mtime'] < tomorrow)
          found = true
        end
      end
      res &&= found
      res
    end

    it "should search with dates ignores new files" do
      res = true
      files = client.fs.file.search(pwd, "*", true, -1, tomorrow, nil)
      files.each do |file|
        res = false if file['name'] == @file_name
      end
      res
    end

    it "should search with dates ignores old files" do
      res = true
      files = client.fs.file.search(pwd, "*", true, -1, nil, yesterday)
      files.each do |file|
        res = false if file['name'] == @file_name
      end
      res
    end

    genesis_str = "3 January 2009 18:15:13 +0000"
    genesis_date = DateTime.parse(genesis_str)
    genesis = genesis_date.to_i

    if session.platform == 'osx'
      osx_genesis_str = genesis_date.strftime("%Y%m%d%H%M.%S")
      cmd_exec("touch -t '#{osx_genesis_str}' #{@file_name}")
    elsif !['windows', 'win'].include?(session.platform)
      cmd_exec("touch -d '#{genesis_str}' #{@file_name}")
    elsif session.priv.present?
      client.priv.fs.set_file_mace(@file_name, genesis)
    else
      vprint_status("Session does not support setting the modified date, skipping exact date tests")
      return
    end

    it "should search with date inclusive of exact date" do
      res = false
      files = client.fs.file.search(pwd, "*", true, -1, genesis, genesis)
      files.each do |file|
        if file['name'] == @file_name
          res = (file['mtime'] == genesis)
        end
      end
      res
    end
  end

end
