module Authentication
  module Strategies
    class UserPassword < Warden::Strategies::Base

      Warden::Manager.serialize_into_session{ |user| user.id }
      Warden::Manager.serialize_from_session{ |id|
        db_manager = env['msf.db_manager']
        db_manager.users(id: id).first
      }

      Warden::Manager.before_failure do |env,opts|
        # change request method to get control to our handler since authentication failure can happen on any request
        env['REQUEST_METHOD'] = 'POST'
      end

      # Check if request contains valid data and should be authenticated.
      # @return [Boolean] true if strategy should be run for the request; otherwise, false.
      def valid?
        params['username'] && params['password']
      end

      # Authenticate the request.
      def authenticate!
        db_manager = env['msf.db_manager']
        user = db_manager.users(username: params['username']).first

        if user.nil? || !db_manager.authenticate_user(id: user.id, password: params['password'])
          fail("Invalid username or password.")
        else
          success!(user)
        end
      end

    end
  end
end
