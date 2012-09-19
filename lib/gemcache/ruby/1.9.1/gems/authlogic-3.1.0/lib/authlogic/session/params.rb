module Authlogic
  module Session
    # This module is responsible for authenticating the user via params, which ultimately allows the user to log in using a URL like the following:
    #
    #   https://www.domain.com?user_credentials=4LiXF7FiGUppIPubBPey
    #
    # Notice the token in the URL, this is a single access token. A single access token is used for single access only, it is not persisted. Meaning the user
    # provides it, Authlogic grants them access, and that's it. If they want access again they need to provide the token again. Authlogic will
    # *NEVER* try to persist the session after authenticating through this method.
    #
    # For added security, this token is *ONLY* allowed for RSS and ATOM requests. You can change this with the configuration. You can also define if
    # it is allowed dynamically by defining a single_access_allowed? method in your controller. For example:
    #
    #   class UsersController < ApplicationController
    #     private
    #       def single_access_allowed?
    #         action_name == "index"
    #       end
    #
    # Also, by default, this token is permanent. Meaning if the user changes their password, this token will remain the same. It will only change
    # when it is explicitly reset.
    #
    # You can modify all of this behavior with the Config sub module.
    module Params
      def self.included(klass)
        klass.class_eval do
          extend Config
          include InstanceMethods
          attr_accessor :single_access
          persist :persist_by_params
        end
      end
      
      # Configuration for the params / single access feature.
      module Config
        # Works exactly like cookie_key, but for params. So a user can login via params just like a cookie or a session. Your URL would look like:
        #
        #   http://www.domain.com?user_credentials=my_single_access_key
        #
        # You can change the "user_credentials" key above with this configuration option. Keep in mind, just like cookie_key, if you supply an id
        # the id will be appended to the front. Check out cookie_key for more details. Also checkout the "Single Access / Private Feeds Access" section in the README.
        #
        # * <tt>Default:</tt> cookie_key
        # * <tt>Accepts:</tt> String
        def params_key(value = nil)
          rw_config(:params_key, value, cookie_key)
        end
        alias_method :params_key=, :params_key
        
        # Authentication is allowed via a single access token, but maybe this is something you don't want for your application as a whole. Maybe this is
        # something you only want for specific request types. Specify a list of allowed request types and single access authentication will only be
        # allowed for the ones you specify.
        #
        # * <tt>Default:</tt> ["application/rss+xml", "application/atom+xml"]
        # * <tt>Accepts:</tt> String of a request type, or :all or :any to allow single access authentication for any and all request types
        def single_access_allowed_request_types(value = nil)
          rw_config(:single_access_allowed_request_types, value, ["application/rss+xml", "application/atom+xml"])
        end
        alias_method :single_access_allowed_request_types=, :single_access_allowed_request_types
      end
      
      # The methods available for an Authlogic::Session::Base object that make up the params / single access feature.
      module InstanceMethods
        private
          def persist_by_params
            return false if !params_enabled?
            self.unauthorized_record = search_for_record("find_by_single_access_token", params_credentials)
            self.single_access = valid?
          end
          
          def params_enabled?
            return false if !params_credentials || !klass.column_names.include?("single_access_token")
            return controller.single_access_allowed? if controller.responds_to_single_access_allowed?
            
            case single_access_allowed_request_types
            when Array
              single_access_allowed_request_types.include?(controller.request_content_type) || single_access_allowed_request_types.include?(:all)
            else
              [:all, :any].include?(single_access_allowed_request_types)
            end
          end
          
          def params_key
            build_key(self.class.params_key)
          end
          
          def single_access?
            single_access == true
          end
          
          def single_access_allowed_request_types
            self.class.single_access_allowed_request_types
          end
          
          def params_credentials
            controller.params[params_key]
          end
      end
    end
  end
end