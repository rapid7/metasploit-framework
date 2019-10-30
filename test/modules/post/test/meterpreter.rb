
require 'msf/core'
require 'rex'

lib = File.join(Msf::Config.install_root, "test", "lib")
$:.push(lib) unless $:.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Testing Meterpreter Stuff',
        'Description'   => %q{ This module will test meterpreter API methods },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'egypt'],
        'Platform'      => [ 'windows', 'linux', 'java' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptBool.new("AddEntropy" , [false, "Add entropy token to file and directory names.", false]),
        OptString.new("BaseFileName" , [true, "File/dir base name", "meterpreter-test"])
      ], self.class)
  end

  #
  # Change directory into a place that we have write access.
  #
  # The +cleanup+ method will change it back. This method is an implementation
  # of post/test/file.rb's method of the same name, but without the Post::File
  # dependency.
  #
  def setup
    @old_pwd = session.fs.dir.getwd
    stat = session.fs.file.stat("/tmp") rescue nil
    if (stat and stat.directory?)
      tmp = "/tmp"
    else
      tmp = session.sys.config.getenv('TEMP')
    end
    vprint_status("Setup: changing working directory to #{tmp}")
    session.fs.dir.chdir(tmp)

    super
  end


  def test_sys_process
    vprint_status("Starting process tests")
    pid = nil

    if session.commands.include? "stdapi_sys_process_getpid"
      it "should return its own process id" do
        pid = session.sys.process.getpid
        vprint_status("Pid: #{pid}")
        true
      end
    else
      print_status("Session doesn't implement getpid, skipping test")
    end

    it "should return a list of processes" do
      ret = true
      list = session.sys.process.get_processes
      ret &&= (list && list.length > 0)
      if session.commands.include? "stdapi_sys_process_getpid"
        pid ||= session.sys.process.getpid
        process = list.find{ |p| p['pid'] == pid }
        vprint_status("PID info: #{process.inspect}")
        ret &&= !(process.nil?)
      else
        vprint_status("Session doesn't implement getpid, skipping sanity check")
      end

      ret
    end

  end

  def test_sys_config
    vprint_status("Starting system config tests")

    it "should return a user id" do
      uid = session.sys.config.getuid
      true
    end

    it "should return a sysinfo Hash" do
      sysinfo = session.sys.config.sysinfo
      true
    end
  end

  def test_net_config
    unless (session.commands.include? "stdapi_net_config_get_interfaces")
      vprint_status("This meterpreter does not implement get_interfaces, skipping tests")
      return
    end

    vprint_status("Starting networking tests")

    it "should return network interfaces" do
      ifaces = session.net.config.get_interfaces
      res = !!(ifaces and ifaces.length > 0)

      res
    end
    it "should have an interface that matches session_host" do
      ifaces = session.net.config.get_interfaces
      res = !!(ifaces and ifaces.length > 0)

      res &&= !! ifaces.find { |iface|
        iface.addrs.find { |addr|
          addr == session.session_host
        }
      }

      res
    end

    if session.commands.include?("stdapi_net_config_get_routes")
      it "should return network routes" do
        routes = session.net.config.get_routes

        routes and routes.length > 0
      end
    end

  end

  def test_fs
    vprint_status("Starting filesystem tests")
    if datastore["AddEntropy"]
      entropy_value = '-' + ('a'..'z').to_a.shuffle[0,8].join
    else
      entropy_value = ""
    end

    it "should return the proper directory separator" do
      sysinfo = session.sys.config.sysinfo
      if sysinfo["OS"] =~ /windows/i
        sep = session.fs.file.separator
        res = (sep == "\\")
      else
        sep = session.fs.file.separator
        res = (sep == "/")
      end

      res
    end

    it "should return the current working directory" do
      wd = session.fs.dir.pwd
      vprint_status("CWD: #{wd}")

      true
    end

    it "should list files in the current directory" do
      session.fs.dir.entries
    end

    it "should stat a directory" do
      dir = session.fs.dir.pwd
      vprint_status("Current directory: #{dir.inspect}")
      s = session.fs.file.stat(dir)
      vprint_status("Stat of current directory: #{s.inspect}")

      s.directory?
    end

    it "should create and remove a dir" do
      dir_name = "#{datastore["BaseFileName"]}-dir#{entropy_value}"
      vprint_status("Directory Name: #{dir_name}")
      session.fs.dir.rmdir(dir_name) rescue nil
      res = create_directory(dir_name)
      if (res)
        session.fs.dir.rmdir(dir_name)
        res &&= !session.fs.dir.entries.include?(dir_name)
        vprint_status("Directory removed successfully")
      end

      res
    end

    it "should change directories" do
      dir_name = "#{datastore["BaseFileName"]}-dir#{entropy_value}"
      vprint_status("Directory Name: #{dir_name}")
      session.fs.dir.rmdir(dir_name) rescue nil
      res = create_directory(dir_name)

      old_wd = session.fs.dir.pwd
      vprint_status("Old CWD: #{old_wd}")

      if res
        session.fs.dir.chdir(dir_name)
        new_wd = session.fs.dir.pwd
        vprint_status("New CWD: #{new_wd}")

        res &&= new_wd.include? dir_name
        if res
          session.fs.dir.chdir("..")
          wd = session.fs.dir.pwd
          vprint_status("Back to old CWD: #{wd}")
        end
      end
      session.fs.dir.rmdir(dir_name)
      res &&= !session.fs.dir.entries.include?(dir_name)
      vprint_status("Directory removed successfully")

      res
    end

    it "should create and remove files" do
      res = true
      file_name = "#{datastore["BaseFileName"]}#{entropy_value}"
      vprint_status("File Name: #{file_name}")
      res &&= session.fs.file.open(file_name, "wb") { |fd|
        fd.write("test")
      }

      vprint_status("Wrote to #{file_name}, checking contents")
      res &&= session.fs.file.open(file_name, "rb") { |fd|
        contents = fd.read
        vprint_status("Wrote #{contents}")
        (contents == "test")
      }

      session.fs.file.rm(file_name)
      res &&= !session.fs.dir.entries.include?(file_name)

      res
    end

    it "should upload a file" do
      res = true
      remote = "#{datastore["BaseFileName"]}-file#{entropy_value}.txt"
      vprint_status("Remote File Name: #{remote}")
      local  = __FILE__
      vprint_status("uploading")
      session.fs.file.upload_file(remote, local)
      vprint_status("done")
      res &&= session.fs.file.exist?(remote)
      vprint_status("remote file exists? #{res.inspect}")

      if res
        fd = session.fs.file.new(remote, "rb")
        uploaded_contents = fd.read
        until (fd.eof?)
          uploaded_contents << fd.read
        end
        fd.close
        original_contents = ::File.read(local)

        res &&= !!(uploaded_contents == original_contents)
      end

      session.fs.file.rm(remote)
      res
    end

    it "should move files" do
      res = true
      src_name = "#{datastore["BaseFileName"]}#{entropy_value}"
      vprint_status("Source File Name: #{src_name}")
      dst_name = "#{src_name}-moved"
      vprint_status("Destination File Name: #{dst_name}")

      # Make sure we don't have leftovers from a previous run
      session.fs.file.rm(src_name) rescue nil
      session.fs.file.rm(dst_name) rescue nil

      # touch a new file
      fd = session.fs.file.open(src_name, "wb")
      fd.close

      session.fs.file.mv(src_name, dst_name)
      entries = session.fs.dir.entries
      res &&= entries.include?(dst_name)
      res &&= !entries.include?(src_name)

      # clean up
      session.fs.file.rm(src_name) rescue nil
      session.fs.file.rm(dst_name) rescue nil

      res
    end

    it "should copy files" do
      res = true
      src_name = "#{datastore["BaseFileName"]}#{entropy_value}"
      vprint_status("Source File Name: #{src_name}")
      dst_name = "#{src_name}-copied"
      vprint_status("Destination File Name: #{dst_name}")

      # Make sure we don't have leftovers from a previous run
      session.fs.file.rm(src_name) rescue nil
      session.fs.file.rm(dst_name) rescue nil

      # touch a new file
      fd = session.fs.file.open(src_name, "wb")
      fd.close

      session.fs.file.cp(src_name, dst_name)
      entries = session.fs.dir.entries
      res &&= entries.include?(dst_name)
      res &&= entries.include?(src_name)

      # clean up
      session.fs.file.rm(src_name) rescue nil
      session.fs.file.rm(dst_name) rescue nil

      res
    end

    it "should do md5 and sha1 of files" do
      res = true
      remote = "#{datastore["BaseFileName"]}-file#{entropy_value}.txt"
      vprint_status("Remote File Name: #{remote}")
      local  = __FILE__
      vprint_status("uploading")
      session.fs.file.upload_file(remote, local)
      vprint_status("done")
      res &&= session.fs.file.exist?(remote)
      vprint_status("remote file exists? #{res.inspect}")

      if res
        remote_md5 = session.fs.file.md5(remote)
        local_md5  = Digest::MD5.digest(::File.read(local))
        remote_sha = session.fs.file.sha1(remote)
        local_sha  = Digest::SHA1.digest(::File.read(local))
        vprint_status("remote md5: #{Rex::Text.to_hex(remote_md5,'')}")
        vprint_status("local md5 : #{Rex::Text.to_hex(local_md5,'')}")
        vprint_status("remote sha: #{Rex::Text.to_hex(remote_sha,'')}")
        vprint_status("local sha : #{Rex::Text.to_hex(local_sha,'')}")
        res &&= (remote_md5 == local_md5)
      end

      session.fs.file.rm(remote)
      res
    end

  end

=begin
  # Sniffer currently crashes on any OS that requires driver signing,
  # i.e. everything vista and newer
  #
  # Disable loading it for now to make it through the rest of the tests.
  #
  def test_sniffer
    begin
      session.core.use "sniffer"
    rescue
      # Not all meterpreters have a sniffer extension, don't count it
      # against them.
      return
    end

    it "should list interfaces for sniffing" do
      session.sniffer.interfaces.kind_of? Array
    end

    # XXX: how do we test this more thoroughly in a generic way?
  end
=end

  def cleanup
    vprint_status("Cleanup: changing working directory back to #{@old_pwd}")
    session.fs.dir.chdir(@old_pwd)
    super
  end

protected

  def create_directory(name)
    res = true

    session.fs.dir.mkdir(name)
    entries = session.fs.dir.entries
    res &&= entries.include?(name)
    res &&= session.fs.file.stat(name).directory?
    if res
      vprint_status("Directory created successfully")
    end

    res
  end


end
