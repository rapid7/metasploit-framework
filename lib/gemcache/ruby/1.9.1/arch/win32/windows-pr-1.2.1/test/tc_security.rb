#####################################################################
# tc_security.rb
#
# Test case for the Windows::Security module.
#####################################################################
require "windows/security"
require "test/unit"

class SecurityFoo
   include Windows::Security
end

class TC_Windows_Security < Test::Unit::TestCase
   def setup
      @foo = SecurityFoo.new
   end

   def test_numeric_constants
      assert_equal(2,  SecurityFoo::ACL_REVISION)
      assert_equal(2,  SecurityFoo::ACL_REVISION2)
      assert_equal(3,  SecurityFoo::ACL_REVISION3)
      assert_equal(4,  SecurityFoo::ACL_REVISION4)
      assert_equal(62, SecurityFoo::ALLOW_ACE_LENGTH)
      assert_equal(4,  SecurityFoo::DACL_SECURITY_INFORMATION)
      assert_equal(4,  SecurityFoo::SE_DACL_PRESENT)
      assert_equal(20, SecurityFoo::SECURITY_DESCRIPTOR_MIN_LENGTH)
      assert_equal(1,  SecurityFoo::SECURITY_DESCRIPTOR_REVISION)
      assert_equal(4026597376, SecurityFoo::GENERIC_RIGHTS_MASK)
      assert_equal(4026531840, SecurityFoo::GENERIC_RIGHTS_CHK)
      assert_equal(2097151, SecurityFoo::REST_RIGHTS_MASK)
   end

   def test_method_constants
      assert_not_nil(SecurityFoo::AddAce)
      assert_not_nil(SecurityFoo::CopySid)
      assert_not_nil(SecurityFoo::GetAce)
      assert_not_nil(SecurityFoo::GetFileSecurity)
      assert_not_nil(SecurityFoo::GetLengthSid)
      assert_not_nil(SecurityFoo::GetSecurityDescriptorControl)
      assert_not_nil(SecurityFoo::GetSecurityDescriptorDacl)
      assert_not_nil(SecurityFoo::InitializeAcl)
      assert_not_nil(SecurityFoo::InitializeSecurityDescriptor)
      assert_not_nil(SecurityFoo::LookupAccountName)
      assert_not_nil(SecurityFoo::LookupAccountSid)
      assert_not_nil(SecurityFoo::SetFileSecurity)
      assert_not_nil(SecurityFoo::SetSecurityDescriptorDacl)
   end

   def test_add_ace
      assert_respond_to(@foo, :AddAce)
   end

   def test_copy_sid
      assert_respond_to(@foo, :CopySid)
   end

   def test_get_ace
      assert_respond_to(@foo, :GetAce)
   end

   def test_get_file_security
      assert_respond_to(@foo, :GetFileSecurity)
   end

   def test_get_length_sid
      assert_respond_to(@foo, :GetLengthSid)
   end

   def test_security_descriptr_control
      assert_respond_to(@foo, :GetSecurityDescriptorControl)
   end

   def test_security_descriptor_dacl
      assert_respond_to(@foo, :GetSecurityDescriptorDacl)
   end

   def test_initialize_acl
      assert_respond_to(@foo, :InitializeAcl)
   end

   def test_initialize_security_descriptor
      assert_respond_to(@foo, :InitializeSecurityDescriptor)
   end

   def test_lookup_account_name
      assert_respond_to(@foo, :LookupAccountName)
   end

   def test_lookup_account_sid
      assert_respond_to(@foo, :LookupAccountSid)
   end

   def test_set_file_security
      assert_respond_to(@foo, :SetFileSecurity)
   end

   def test_set_security_descriptor_dacl
      assert_respond_to(@foo, :SetSecurityDescriptorDacl)
   end

   def teardown
      @foo = nil
   end
end
