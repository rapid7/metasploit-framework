#####################################################################
# tc_security_authentication.rb
#
# Test case for the Windows::Security::Authentication module.
#####################################################################
require 'windows/security/authentication'
require 'test/unit'

class TC_Windows_Security_Authentication < Test::Unit::TestCase

   include Windows::Security::Authentication

   def test_methods
      assert_respond_to(self, :LsaOpenPolicy)
      assert_respond_to(self, :LsaClose)
      assert_respond_to(self, :LsaNtStatusToWinError)
   end

   def test_constants
      assert_not_nil(POLICY_VIEW_LOCAL_INFORMATION)
      assert_not_nil(POLICY_VIEW_AUDIT_INFORMATION)
      assert_not_nil(POLICY_GET_PRIVATE_INFORMATION)
      assert_not_nil(POLICY_TRUST_ADMIN)
      assert_not_nil(POLICY_CREATE_ACCOUNT)
      assert_not_nil(POLICY_CREATE_SECRET)
      assert_not_nil(POLICY_CREATE_PRIVILEGE)
      assert_not_nil(POLICY_SET_DEFAULT_QUOTA_LIMITS)
      assert_not_nil(POLICY_SET_AUDIT_REQUIREMENTS)
      assert_not_nil(POLICY_AUDIT_LOG_ADMIN)
      assert_not_nil(POLICY_SERVER_ADMIN)
      assert_not_nil(POLICY_LOOKUP_NAMES)
      assert_not_nil(POLICY_NOTIFICATION)
   end
end
