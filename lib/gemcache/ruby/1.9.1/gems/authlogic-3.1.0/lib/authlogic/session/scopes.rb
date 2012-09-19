module Authlogic
  module Session
    # Authentication can be scoped, and it's easy, you just need to define how you want to scope everything. This should help you:
    #
    # 1. Want to scope by a parent object? Ex: An account has many users. Checkout Authlogic::AuthenticatesMany
    # 2. Want to scope the validations in your model? Ex: 2 users can have the same login under different accounts. See Authlogic::ActsAsAuthentic::Scope
    module Scopes # :nodoc:
      def self.included(klass)
        klass.class_eval do
          extend ClassMethods
          include InstanceMethods
          attr_writer :scope
        end
      end

      # = Scopes
      module ClassMethods
        # The current scope set, should be used in the block passed to with_scope.
        def scope
          Thread.current[:authlogic_scope]
        end

        # What with_scopes focuses on is scoping the query when finding the object and the name of the cookie / session. It works very similar to
        # ActiveRecord::Base#with_scopes. It accepts a hash with any of the following options:
        #
        # * <tt>find_options:</tt> any options you can pass into ActiveRecord::Base.find. This is used when trying to find the record.
        # * <tt>id:</tt> The id of the session, this gets merged with the real id. For information ids see the id method.
        #
        # Here is how you use it:
        #
        #   UserSession.with_scope(:find_options => {:conditions => "account_id = 2"}, :id => "account_2") do
        #     UserSession.find
        #   end
        #
        # Eseentially what the above does is scope the searching of the object with the sql you provided. So instead of:
        #
        #   User.where("login = 'ben'").first
        #
        # it would be:
        #
        #   User.where("login = 'ben' and account_id = 2").first
        #
        # You will also notice the :id option. This works just like the id method. It scopes your cookies. So the name of your cookie will be:
        #
        #   account_2_user_credentials
        #
        # instead of:
        #
        #   user_credentials
        #
        # What is also nifty about scoping with an :id is that it merges your id's. So if you do:
        #
        #   UserSession.with_scope(:find_options => {:conditions => "account_id = 2"}, :id => "account_2") do
        #     session = UserSession.new
        #     session.id = :secure
        #   end
        #
        # The name of your cookies will be:
        #
        #   secure_account_2_user_credentials
        def with_scope(options = {}, &block)
          raise ArgumentError.new("You must provide a block") unless block_given?
          self.scope = options
          result = yield
          self.scope = nil
          result
        end

        private
          def scope=(value)
            Thread.current[:authlogic_scope] = value
          end
      end

      module InstanceMethods
        # Setting the scope if it exists upon instantiation.
        def initialize(*args)
          self.scope = self.class.scope
          super
        end

        # The scope of the current object
        def scope
          @scope ||= {}
        end

        private
          # Used for things like cookie_key, session_key, etc.
          def build_key(last_part)
            [scope[:id], super].compact.join("_")
          end

          def search_for_record(*args)
            klass.send(:with_scope, :find => (scope[:find_options] || {})) do
              klass.send(*args)
            end
          end
      end
    end
  end
end