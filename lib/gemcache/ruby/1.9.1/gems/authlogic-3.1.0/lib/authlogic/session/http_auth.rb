module Authlogic
  module Session
    # Handles all authentication that deals with basic HTTP auth. Which is authentication built into the HTTP protocol:
    #
    #   http://username:password@whatever.com
    #
    # Also, if you are not comfortable letting users pass their raw username and password you can always use the single
    # access token. See Authlogic::Session::Params for more info.
    module HttpAuth
      def self.included(klass)
        klass.class_eval do
          extend Config
          include InstanceMethods
          persist :persist_by_http_auth, :if => :persist_by_http_auth?
        end
      end
      
      # Configuration for the HTTP basic auth feature of Authlogic.
      module Config
        # Do you want to allow your users to log in via HTTP basic auth?
        #
        # I recommend keeping this enabled. The only time I feel this should be disabled is if you are not comfortable
        # having your users provide their raw username and password. Whatever the reason, you can disable it here.
        #
        # * <tt>Default:</tt> true
        # * <tt>Accepts:</tt> Boolean
        def allow_http_basic_auth(value = nil)
          rw_config(:allow_http_basic_auth, value, true)
        end
        alias_method :allow_http_basic_auth=, :allow_http_basic_auth

        # Whether or not to request HTTP authentication
        #
        # If set to true and no HTTP authentication credentials are sent with
        # the request, the Rails controller method
        # authenticate_or_request_with_http_basic will be used and a '401
        # Authorization Required' header will be sent with the response.  In
        # most cases, this will cause the classic HTTP authentication popup to
        # appear in the users browser.
        #
        # If set to false, the Rails controller method
        # authenticate_with_http_basic is used and no 401 header is sent.
        #
        # Note: This parameter has no effect unless allow_http_basic_auth is
        # true
        #
        # * <tt>Default:</tt> false
        # * <tt>Accepts:</tt> Boolean
        def request_http_basic_auth(value = nil)
          rw_config(:request_http_basic_auth, value, false)
        end
        alias_method :request_http_basic_auth=, :request_http_basic_auth

        # HTTP authentication realm
        #
        # Sets the HTTP authentication realm.
        #
        # Note: This option has no effect unless request_http_basic_auth is true
        #
        # * <tt>Default:</tt> 'Application'
        # * <tt>Accepts:</tt> String
        def http_basic_auth_realm(value = nil)
          rw_config(:http_basic_auth_realm, value, 'Application')
        end
        alias_method :http_basic_auth_realm=, :http_basic_auth_realm
      end
      
      # Instance methods for the HTTP basic auth feature of authlogic.
      module InstanceMethods
        private
          def persist_by_http_auth?
            allow_http_basic_auth? && login_field && password_field
          end
        
          def persist_by_http_auth
            login_proc = Proc.new do |login, password|
              if !login.blank? && !password.blank?
                send("#{login_field}=", login)
                send("#{password_field}=", password)
                valid?
              end
            end

            if self.class.request_http_basic_auth
              controller.authenticate_or_request_with_http_basic(self.class.http_basic_auth_realm, &login_proc)
            else
              controller.authenticate_with_http_basic(&login_proc)
            end
        
            false
          end
        
          def allow_http_basic_auth?
            self.class.allow_http_basic_auth == true
          end
      end
    end
  end
end
