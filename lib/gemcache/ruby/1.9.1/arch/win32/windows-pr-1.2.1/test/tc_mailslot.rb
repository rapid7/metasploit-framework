#####################################################################
# tc_mailslot.rb
#
# Test case for the Windows::Mailslot module.
#####################################################################
require 'windows/mailslot'
require 'test/unit'

class TC_Windows_Mailslot < Test::Unit::TestCase
   include Windows::Mailslot

   def test_constants
      assert_equal(0xFFFFFFFF, MAILSLOT_WAIT_FOREVER)
      assert_equal(0xFFFFFFFF, MAILSLOT_NO_MESSAGE)
   end

   def test_methods
      assert_respond_to(self, :CreateMailslot)
      assert_respond_to(self, :GetMailslotInfo)
      assert_respond_to(self, :SetMailslotInfo)
   end
end
