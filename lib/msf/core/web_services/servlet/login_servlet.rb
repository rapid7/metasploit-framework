module Msf::WebServices::LoginServlet

  def self.api_path
    '/api/v1/logins'
  end

  def self.api_path_with_id
    "#{self.api_path}/?:id?"
  end

  def self.registered(app)
    app.get self.api_path, &get_logins
    app.get self.api_path_with_id, &get_logins
    app.post self.api_path, &create_login
    app.put self.api_path_with_id, &update_login
    app.delete self.api_path, &delete_logins
  end

  #######
  private
  #######

  def self.get_logins
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.logins(sanitized_params)
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving logins:', code: 500)
      end
    }
  end

  def self.create_login
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        opts[:core][:workspace] = get_db.workspaces(id: opts[:workspace_id]).first
        opts[:core] = get_db.creds(opts[:core]).first
        data = get_db.create_credential_login(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error creating the login:', code: 500)
      end
    }
  end

  def self.update_login
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_login(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the login:', code: 500)
      end
    }
  end

  def self.delete_logins
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_logins(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the logins:', code: 500)
      end
    }
  end
end
