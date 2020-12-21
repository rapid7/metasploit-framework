module Msf::WebServices::AuthServlet

  def self.api_path
    '/api/v1/auth'
  end

  def self.api_account_path
    "#{self.api_path}/account"
  end

  def self.api_login_path
    "#{self.api_path}/login"
  end

  def self.api_logout_path
    "#{self.api_path}/logout"
  end

  def self.api_generate_token_path
    "#{self.api_path}/generate-token"
  end

  def self.api_unauthenticated_path
    "#{self.api_path}/unauthenticated"
  end

  def self.registered(app)
    app.get self.api_account_path, &get_api_account

    app.get self.api_login_path, &get_login
    app.post self.api_login_path, &post_login

    app.get self.api_logout_path, &get_logout
    app.post self.api_generate_token_path, &post_generate_token
    app.post "#{self.api_unauthenticated_path}/?:scope?", &post_unauthenticated
  end

  #######
  private
  #######

  # Get account page
  def self.get_api_account
    lambda {
      erb :'auth/account'
    }
  end

  # Get login page
  def self.get_login
    lambda {
      erb :'auth/login'
    }
  end

  # Process login request
  def self.post_login
    lambda {
      warden.authenticate!(scope: :user)

      if session[:return_to].nil? || session[:return_to] == self.api_login_path
        redirect self.api_account_path
      else
        redirect session[:return_to]
      end
    }
  end

  # Process user log out
  def self.get_logout
    lambda {
      warden.logout
      redirect self.api_account_path
    }
  end

  # Generate a new API token for the current user
  def self.post_generate_token
    lambda {
      # change action to drop the scope param since this is used
      # by XMLHttpRequest (XHR) and we don't want a redirect
      warden.authenticate!(scope: :user, action: self.api_unauthenticated_path)
      token = get_db.create_new_user_token(id: warden.user(:user).id, token_length: 40)
      set_json_data_response(response: {message: "Generated new API token.", token: token})
    }
  end

  # Handle the unauthenticated action for multiple scopes
  def self.post_unauthenticated
    lambda {
      if !params['scope'].nil? && params['scope'] == 'user'
        session[:return_to] = warden_options[:attempted_path] if session[:return_to].nil?
        redirect self.api_login_path
      end

      msg = warden_options[:message]
      code = warden_options[:code] || 401
      error = {
        code: code,
        message: "#{!msg.nil? ? "#{msg} " : nil}Authenticate to access this resource."
      }
      set_json_error_response(response: error, code: error[:code])
    }
  end

end
