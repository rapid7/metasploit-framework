require 'json'

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
        begin
          body = JSON.parse(request.body.read, symbolize_names: true)
          body[:username] && body[:password]
        ensure
          request.body.rewind # Reset the StringIO buffer so any further consumers can read the body
        end
      end

      # Authenticate the request.
      def authenticate!
        begin
          body = JSON.parse(request.body.read, symbolize_names: true)

          db_manager = env['msf.db_manager']
          user = db_manager.users(username: body[:username]).first

          if user.nil? || !db_manager.authenticate_user(id: user.id, password: body[:password])
            fail("Invalid username or password.")
          else
            success!(user)
          end
        ensure
          request.body.rewind # Reset the StringIO buffer so any further consumers can read the body
        end
      end
    end
  end
end
