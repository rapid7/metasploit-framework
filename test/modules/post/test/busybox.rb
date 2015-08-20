require 'msf/core'

lib = File.join(Msf::Config.install_root, "test", "lib")
$:.push(lib) unless $:.include?(lib)
require 'module_test'

load 'test/lib/module_test.rb'
#load 'lib/rex/text.rb'
#load 'lib/msf/core/post/file.rb'

class Metasploit4 < Msf::Post

  include Msf::Post::Linux::Busybox

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Testing BusyBox Management Functions',
        'Description'   => %q{ This module will test Post::Linux::BusyBox API methods },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Javier Vicente Vallejo'],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell' ]
      ))

    register_options(
      [
        OptString.new("BaseFileName" , [true, "File name to create", "busybox_test"])
      ], self.class)
  end


  def test_busybox_file_system_management

    it "should test for file existence" do
      ret = false
      ret = true if file_exists("/etc/passwd")
      ret
    end

    it "should find a writable directory" do
      ret = false
      ret = true if nil != get_writable_directory()
      ret
    end

    it "should write and append data to a file in a writable directory" do
      ret = false
      writable_directory = get_writable_directory()
      if nil != writable_directory
        writable_file = writable_directory + datastore["BaseFileName"]
        if is_writable_and_write(writable_file, "test write ", false) and "test write " == read_file(writable_file) and
           is_writable_and_write(writable_file, "test append", true)  and "test write test append" == read_file(writable_file)
          ret = true
        end
        cmd_exec("rm -f #{writable_file}")
      end
      ret
    end

  end

end

