#####################################################################
# tc_directory.rb
#
# Test case for the Windows::Directory module.
#####################################################################
require 'windows/directory'
require 'test/unit'

class DirectoryFoo
   include Windows::Directory
end

class TC_Windows_Directory < Test::Unit::TestCase
   def setup
      @foo  = DirectoryFoo.new
   end

   def test_method_constants
      assert_not_nil(DirectoryFoo::CreateDirectory)
   end

   def teardown
      @foo  = nil
   end
end
