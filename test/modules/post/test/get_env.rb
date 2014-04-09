
$:.push "test/lib" unless $:.include? "test/lib"
require 'module_test'

#load 'test/lib/module_test.rb'
#load 'lib/rex/text.rb'
#load 'lib/msf/core/post/common.rb'

class Metasploit4 < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Test Post::Common Get Envs',
        'Description'   => %q{ This module will test Post::Common get envs API methods },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Ben Campbell'],
        'Platform'      => [ 'windows', 'linux', 'java', 'python' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
      ))
  end

  def test_get_env_windows
    if session.platform =~ /win/i
      it "should return windows path" do
        path = get_env('WINDIR')
        path =~ /windows/i
      end

      it "should handle % signs" do
        path = get_env('%WINDIR%')
        path =~ /windows/i
      end
    end
  end

  def test_get_env_nix
    unless session.platform =~ /win/i
      it "should return user" do
        user = get_env('USER')
        !user.blank?
     end

      it "should handle $ sign" do
        user = get_env('$USER')
        !user.blank?
      end
    end
  end

  def test_get_envs
    it "should return multiple envs" do
      res = get_envs('PATH','USERNAME')
      !res['PATH'].blank? && !res['USERNAME'].blank?
    end
  end

end

