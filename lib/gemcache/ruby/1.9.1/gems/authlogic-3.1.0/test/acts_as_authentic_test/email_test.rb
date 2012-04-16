require 'test_helper'

module ActsAsAuthenticTest
  class EmailTest < ActiveSupport::TestCase
    def test_email_field_config
      assert_equal :email, User.email_field
      assert_equal :email, Employee.email_field

      User.email_field = :nope
      assert_equal :nope, User.email_field
      User.email_field :email
      assert_equal :email, User.email_field
    end

    def test_validate_email_field_config
      assert User.validate_email_field
      assert Employee.validate_email_field

      User.validate_email_field = false
      assert !User.validate_email_field
      User.validate_email_field true
      assert User.validate_email_field
    end

    def test_validates_length_of_email_field_options_config
      assert_equal({:maximum => 100}, User.validates_length_of_email_field_options)
      assert_equal({:maximum => 100}, Employee.validates_length_of_email_field_options)

      User.validates_length_of_email_field_options = {:yes => "no"}
      assert_equal({:yes => "no"}, User.validates_length_of_email_field_options)
      User.validates_length_of_email_field_options({:within => 6..100})
      assert_equal({:within => 6..100}, User.validates_length_of_email_field_options)
    end

    def test_validates_format_of_email_field_options_config
      default = {:with => Authlogic::Regex.email, :message => I18n.t('error_messages.email_invalid', :default => "should look like an email address.")}
      assert_equal default, User.validates_format_of_email_field_options
      assert_equal default, Employee.validates_format_of_email_field_options

      User.validates_format_of_email_field_options = {:yes => "no"}
      assert_equal({:yes => "no"}, User.validates_format_of_email_field_options)
      User.validates_format_of_email_field_options default
      assert_equal default, User.validates_format_of_email_field_options
    end

    def test_validates_uniqueness_of_email_field_options_config
      default = {:case_sensitive => false, :scope => Employee.validations_scope, :if => "#{Employee.email_field}_changed?".to_sym}
      assert_equal default, Employee.validates_uniqueness_of_email_field_options

      Employee.validates_uniqueness_of_email_field_options = {:yes => "no"}
      assert_equal({:yes => "no"}, Employee.validates_uniqueness_of_email_field_options)
      Employee.validates_uniqueness_of_email_field_options default
      assert_equal default, Employee.validates_uniqueness_of_email_field_options
    end

    def test_validates_length_of_email_field
      u = User.new
      u.email = "a@a.a"
      assert !u.valid?
      assert u.errors[:email].size > 0

      u.email = "a@a.com"
      assert !u.valid?
      assert u.errors[:email].size == 0
    end

    def test_validates_format_of_email_field
      u = User.new
      u.email = "aaaaaaaaaaaaa"
      u.valid?
      assert u.errors[:email].size > 0

      u.email = "a@a.com"
      u.valid?
      assert u.errors[:email].size == 0

      u.email = "damien+test1...etc..@mydomain.com"
      u.valid?
      assert u.errors[:email].size == 0

      u.email = "dakota.dux+1@gmail.com"
      u.valid?
      assert u.errors[:email].size == 0

      u.email = "dakota.d'ux@gmail.com"
      u.valid?
      assert u.errors[:email].size == 0
    end

    def test_validates_uniqueness_of_email_field
      u = User.new
      u.email = "bjohnson@binarylogic.com"
      assert !u.valid?
      assert u.errors[:email].size > 0

      u.email = "BJOHNSON@binarylogic.com"
      assert !u.valid?
      assert u.errors[:email].size > 0

      u.email = "a@a.com"
      assert !u.valid?
      assert u.errors[:email].size == 0
    end
  end
end