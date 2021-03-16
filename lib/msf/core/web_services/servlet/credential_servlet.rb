module Msf::WebServices::CredentialServlet

  def self.api_path
    '/api/v1/credentials'
  end

  def self.api_path_with_id
    "#{self.api_path}/?:id?"
  end

  def self.registered(app)
    app.get self.api_path, &get_credentials
    app.get self.api_path_with_id, &get_credentials
    app.post self.api_path, &create_credential
    app.put self.api_path_with_id, &update_credential
    app.delete self.api_path, &delete_credentials
  end

  #######
  private
  #######

  def self.get_credentials
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.creds(sanitized_params)
        includes = [:logins, :public, :private, :realm]
        # Need to append the human attribute into the private sub-object before converting to json
        # This is normally pulled from a class method from the MetasploitCredential class
        response = []
        data.each do |cred|
          json = cred.as_json(include: includes).merge(private_class: cred.private.class.to_s)
          response << json
        end
        data = data.first if is_single_object?(data, sanitized_params)
        response = format_cred_json(data)
        set_json_data_response(response: response)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving credentials:', code: 500)
      end
    }
  end

  def self.create_credential
    lambda {
      warden.authenticate!
      job = lambda { |opts|
        opts[:origin_type] = opts[:origin_type].to_sym if opts[:origin_type]
        opts[:private_type] = opts[:private_type].to_sym if opts[:private_type]
        get_db.create_credential(opts)
      }
      exec_report_job(request, &job)
    }
  end

  def self.update_credential
    lambda {
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_credential(opts)
        response = format_cred_json(data)
        set_json_data_response(response: response.first)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the credential:', code: 500)
      end
    }
  end

  def self.delete_credentials
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_credentials(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the credential:', code: 500)
      end
    }
  end
end
