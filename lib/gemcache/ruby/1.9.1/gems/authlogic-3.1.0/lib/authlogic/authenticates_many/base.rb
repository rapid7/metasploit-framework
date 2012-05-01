module Authlogic
  # This allows you to scope your authentication. For example, let's say all users belong to an account, you want to make sure only users
  # that belong to that account can actually login into that account. Simple, just do:
  #
  #   class Account < ActiveRecord::Base
  #     authenticates_many :user_sessions
  #   end
  #
  # Now you can scope sessions just like everything else in ActiveRecord:
  #
  #   @account.user_sessions.new(*args)
  #   @account.user_sessions.create(*args)
  #   @account.user_sessions.find(*args)
  #   # ... etc
  #
  # Checkout the authenticates_many method for a list of options.
  # You may also want to checkout Authlogic::ActsAsAuthentic::Scope to scope your model.
  module AuthenticatesMany
    module Base
      # Allows you set essentially set up a relationship with your sessions. See module definition above for more details.
      #
      # === Options
      #
      # * <tt>session_class:</tt> default: "#{name}Session",
      #   This is the related session class.
      #
      # * <tt>relationship_name:</tt> default: options[:session_class].klass_name.underscore.pluralize,
      #   This is the name of the relationship you want to use to scope everything. For example an Account has many Users. There should be a relationship
      #   called :users that you defined with a has_many. The reason we use the relationship is so you don't have to repeat yourself. The relatonship
      #   could have all kinds of custom options. So instead of repeating yourself we essentially use the scope that the relationship creates.
      #
      # * <tt>find_options:</tt> default: nil,
      #   By default the find options are created from the relationship you specify with :relationship_name. But if you want to override this and
      #   manually specify find_options you can do it here. Specify options just as you would in ActiveRecord::Base.find.
      #
      # * <tt>scope_cookies:</tt> default: false
      #   By the nature of cookies they scope theirself if you are using subdomains to access accounts. If you aren't using subdomains you need to have
      #   separate cookies for each account, assuming a user is logging into mroe than one account. Authlogic can take care of this for you by
      #   prefixing the name of the cookie and sessin with the model id. You just need to tell Authlogic to do this by passing this option.
      def authenticates_many(name, options = {})
        options[:session_class] ||= name.to_s.classify.constantize
        options[:relationship_name] ||= options[:session_class].klass_name.underscore.pluralize
        class_eval <<-"end_eval", __FILE__, __LINE__
          def #{name}
            find_options = #{options[:find_options].inspect} || #{options[:relationship_name]}.scoped
            @#{name} ||= Authlogic::AuthenticatesMany::Association.new(#{options[:session_class]}, find_options, #{options[:scope_cookies] ? "self.class.model_name.underscore + '_' + self.send(self.class.primary_key).to_s" : "nil"})
          end
        end_eval
      end
    end

    ::ActiveRecord::Base.extend(Base) if defined?(::ActiveRecord)
  end
end