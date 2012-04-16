require "authlogic/i18n/translator"

module Authlogic
  # This class allows any message in Authlogic to use internationalization. In earlier versions of Authlogic each message was translated via configuration.
  # This cluttered up the configuration and cluttered up Authlogic. So all translation has been extracted out into this class. Now all messages pass through
  # this class, making it much easier to implement in I18n library / plugin you want. Use this as a layer that sits between Authlogic and whatever I18n
  # library you want to use.
  #
  # By default this uses the rails I18n library, if it exists. If it doesnt exist it just returns the default english message. The Authlogic I18n class
  # works EXACTLY like the rails I18n class. This is because the arguments are delegated to this class.
  #
  # Here is how all messages are translated internally with Authlogic:
  #
  #   Authlogic::I18n.t('error_messages.password_invalid', :default => "is invalid")
  #
  # If you use a different I18n library just replace the build-in I18n::Translator class with your own. For example:
  #
  #   class MyAuthlogicI18nTranslator
  #     def translate(key, options = {})
  #       # you will have key which will be something like: "error_messages.password_invalid"
  #       # you will also have options[:default], which will be the default english version of the message
  #       # do whatever you want here with the arguments passed to you.
  #     end
  #   end
  #   
  #   Authlogic::I18n.translator = MyAuthlogicI18nTranslator.new
  #
  # That it's! Here is a complete list of the keys that are passed. Just define these however you wish:
  #
  #   authlogic:
  #     error_messages:
  #       login_blank: can not be blank
  #       login_not_found: is not valid
  #       login_invalid: should use only letters, numbers, spaces, and .-_@ please.
  #       consecutive_failed_logins_limit_exceeded: Consecutive failed logins limit exceeded, account is disabled.
  #       email_invalid: should look like an email address.
  #       password_blank: can not be blank
  #       password_invalid: is not valid
  #       not_active: Your account is not active
  #       not_confirmed: Your account is not confirmed
  #       not_approved: Your account is not approved
  #       no_authentication_details: You did not provide any details for authentication.
  #       general_credentials_error: Login/Password combination is not valid
  #     models:
  #       user_session: UserSession (or whatever name you are using)
  #     attributes:
  #       user_session: (or whatever name you are using)
  #         login: login
  #         email: email
  #         password: password
  #         remember_me: remember me
  module I18n
    @@scope = :authlogic
    @@translator = nil
    
    class << self
      # Returns the current scope. Defaults to :authlogic
      def scope
        @@scope
      end
   
      # Sets the current scope. Used to set a custom scope.
      def scope=(scope)
        @@scope = scope
      end
      
      # Returns the current translator. Defaults to +Translator+.
      def translator
        @@translator ||= Translator.new
      end
      
      # Sets the current translator. Used to set a custom translator.
      def translator=(translator)
        @@translator = translator
      end
    
      # All message translation is passed to this method. The first argument is the key for the message. The second is options, see the rails I18n library for a list of options used.
      def translate(key, options = {})
        translator.translate key, { :scope => I18n.scope }.merge(options)
      end
      alias :t :translate
    end
  end
end
