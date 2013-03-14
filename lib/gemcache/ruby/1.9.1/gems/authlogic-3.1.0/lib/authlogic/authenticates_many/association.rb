module Authlogic
  module AuthenticatesMany
    # An object of this class is used as a proxy for the authenticates_many relationship. It basically allows you to "save" scope details
    # and call them on an object, which allows you to do the following:
    #
    #   @account.user_sessions.new
    #   @account.user_sessions.find
    #   # ... etc
    #
    # You can call all of the class level methods off of an object with a saved scope, so that calling the above methods scopes the user
    # sessions down to that specific account. To implement this via ActiveRecord do something like:
    #
    #   class User < ActiveRecord::Base
    #     authenticates_many :user_sessions
    #   end
    class Association
      attr_accessor :klass, :find_options, :id
      
      def initialize(klass, find_options, id)
        self.klass = klass
        self.find_options = find_options
        self.id = id
      end
      
      [:create, :create!, :find, :new].each do |method|
        class_eval <<-"end_eval", __FILE__, __LINE__
          def #{method}(*args)
            klass.with_scope(scope_options) do
              klass.#{method}(*args)
            end
          end
        end_eval
      end
      alias_method :build, :new
    
      private
        def scope_options
          {:find_options => find_options, :id => id}
        end
    end
  end
end