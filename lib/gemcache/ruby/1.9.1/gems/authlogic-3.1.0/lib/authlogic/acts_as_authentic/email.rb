module Authlogic
  module ActsAsAuthentic
    # Sometimes models won't have an explicit "login" or "username" field. Instead they want to use the email field.
    # In this case, authlogic provides validations to make sure the email submited is actually a valid email. Don't worry,
    # if you do have a login or username field, Authlogic will still validate your email field. One less thing you have to
    # worry about.
    module Email
      def self.included(klass)
        klass.class_eval do
          extend Config
          add_acts_as_authentic_module(Methods)
        end
      end

      # Configuration to modify how Authlogic handles the email field.
      module Config
        # The name of the field that stores email addresses.
        #
        # * <tt>Default:</tt> :email, if it exists
        # * <tt>Accepts:</tt> Symbol
        def email_field(value = nil)
          rw_config(:email_field, value, first_column_to_exist(nil, :email, :email_address))
        end
        alias_method :email_field=, :email_field

        # Toggles validating the email field or not.
        #
        # * <tt>Default:</tt> true
        # * <tt>Accepts:</tt> Boolean
        def validate_email_field(value = nil)
          rw_config(:validate_email_field, value, true)
        end
        alias_method :validate_email_field=, :validate_email_field

        # A hash of options for the validates_length_of call for the email field. Allows you to change this however you want.
        #
        # <b>Keep in mind this is ruby. I wanted to keep this as flexible as possible, so you can completely replace the hash or
        # merge options into it. Checkout the convenience function merge_validates_length_of_email_field_options to merge
        # options.</b>
        #
        # * <tt>Default:</tt> {:maximum => 100}
        # * <tt>Accepts:</tt> Hash of options accepted by validates_length_of
        def validates_length_of_email_field_options(value = nil)
          rw_config(:validates_length_of_email_field_options, value, {:maximum => 100})
        end
        alias_method :validates_length_of_email_field_options=, :validates_length_of_email_field_options

        # A convenience function to merge options into the validates_length_of_email_field_options. So intead of:
        #
        #   self.validates_length_of_email_field_options = validates_length_of_email_field_options.merge(:my_option => my_value)
        #
        # You can do this:
        #
        #   merge_validates_length_of_email_field_options :my_option => my_value
        def merge_validates_length_of_email_field_options(options = {})
          self.validates_length_of_email_field_options = validates_length_of_email_field_options.merge(options)
        end

        # A hash of options for the validates_format_of call for the email field. Allows you to change this however you want.
        #
        # <b>Keep in mind this is ruby. I wanted to keep this as flexible as possible, so you can completely replace the hash or
        # merge options into it. Checkout the convenience function merge_validates_format_of_email_field_options to merge
        # options.</b>
        #
        # * <tt>Default:</tt> {:with => Authlogic::Regex.email, :message => lambda {I18n.t('error_messages.email_invalid', :default => "should look like an email address.")}}
        # * <tt>Accepts:</tt> Hash of options accepted by validates_format_of
        def validates_format_of_email_field_options(value = nil)
          rw_config(:validates_format_of_email_field_options, value, {:with => Authlogic::Regex.email, :message => I18n.t('error_messages.email_invalid', :default => "should look like an email address.")})
        end
        alias_method :validates_format_of_email_field_options=, :validates_format_of_email_field_options

        # See merge_validates_length_of_email_field_options. The same thing except for validates_format_of_email_field_options.
        def merge_validates_format_of_email_field_options(options = {})
          self.validates_format_of_email_field_options = validates_format_of_email_field_options.merge(options)
        end

        # A hash of options for the validates_uniqueness_of call for the email field. Allows you to change this however you want.
        #
        # <b>Keep in mind this is ruby. I wanted to keep this as flexible as possible, so you can completely replace the hash or
        # merge options into it. Checkout the convenience function merge_validates_uniqueness_of_email_field_options to merge
        # options.</b>
        #
        # * <tt>Default:</tt> {:case_sensitive => false, :scope => validations_scope, :if => "#{email_field}_changed?".to_sym}
        # * <tt>Accepts:</tt> Hash of options accepted by validates_uniqueness_of
        def validates_uniqueness_of_email_field_options(value = nil)
          rw_config(:validates_uniqueness_of_email_field_options, value, {:case_sensitive => false, :scope => validations_scope, :if => "#{email_field}_changed?".to_sym})
        end
        alias_method :validates_uniqueness_of_email_field_options=, :validates_uniqueness_of_email_field_options

        # See merge_validates_length_of_email_field_options. The same thing except for validates_uniqueness_of_email_field_options.
        def merge_validates_uniqueness_of_email_field_options(options = {})
          self.validates_uniqueness_of_email_field_options = validates_uniqueness_of_email_field_options.merge(options)
        end
      end

      # All methods relating to the email field
      module Methods
        def self.included(klass)
          klass.class_eval do
            if validate_email_field && email_field
              validates_length_of email_field, validates_length_of_email_field_options
              validates_format_of email_field, validates_format_of_email_field_options
              validates_uniqueness_of email_field, validates_uniqueness_of_email_field_options
            end
          end
        end
      end
    end
  end
end