require 'rack/protection'

module Rack
  module Protection
    ##
    # Prevented attack::   CSRF
    # Supported browsers:: all
    # More infos::         http://en.wikipedia.org/wiki/Cross-site_request_forgery
    #
    # Only accepts unsafe HTTP requests if a given access token matches the token
    # included in the session.
    #
    # Compatible with Rails and rack-csrf.
    #
    # Options:
    #
    # authenticity_param: Defines the param's name that should contain the token on a request.
    #
    class AuthenticityToken < Base
      default_options :authenticity_param => 'authenticity_token'

      def accepts?(env)
        session = session env
        token   = session[:csrf] ||= session['_csrf_token'] || random_string
        safe?(env) ||
          secure_compare(env['HTTP_X_CSRF_TOKEN'].to_s, token) ||
          secure_compare(Request.new(env).params[options[:authenticity_param]].to_s, token)
      end
    end
  end
end
