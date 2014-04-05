
$:.push "test/lib" unless $:.include? "test/lib"
require 'module_test'

#load 'test/lib/module_test.rb'
#load 'lib/rex/text.rb'
#load 'lib/msf/core/post/linux/system.rb'
#load 'lib/msf/core/post/unix/enum_user_dirs.rb'

class Metasploit4 < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::Post::Linux::System
  include Msf::Post::Unix
  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Testing Remote Unix System Manipulation',
        'Description'   => %q{ This module will test Post::File API methods },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'egypt'],
        'Platform'      => [ 'linux', 'java' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
      ))
  end

  def test_unix
    it "should list users" do
      ret = true
      users = get_users
      ret &&= users.kind_of? Array
      ret &&= users.length > 0
      have_root = false
      if ret
        users.each { |u|
          next unless u[:name] == "root"
          have_root = true
        }
      end
      ret
      ret &&= have_root

      ret
    end

  end

end

