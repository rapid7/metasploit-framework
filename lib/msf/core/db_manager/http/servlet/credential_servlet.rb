module CredentialServlet

  def self.api_path
    '/api/v1/credentials'
  end

  def self.api_path_with_id
    "#{CredentialServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get CredentialServlet.api_path, &get_credentials
    app.post CredentialServlet.api_path, &create_credential
    app.put CredentialServlet.api_path_with_id, &update_credential
    app.delete CredentialServlet.api_path, &delete_credentials
  end

  #######
  private
  #######

  def self.get_credentials
    lambda {
      begin
        opts = parse_json_request(request, false)
        sanitized_params = sanitize_params(params)
        opts.merge!(sanitized_params)
        data = get_db.creds(opts)

        # Need to append the human attribute into the private sub-object before converting to json
        # This is normally pulled from a class method from the MetasploitCredential class
        response = format_cred_json(data)
        set_json_response(response)
      rescue => e
        set_error_on_response(e)
      end
    }
  end

  def self.create_credential
    lambda {
      job = lambda { |opts|
        opts[:origin_type] = opts[:origin_type].to_sym
        opts[:private_type] = opts[:private_type].to_sym
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
        set_json_response(response.first)
      rescue => e
        set_error_on_response(e)
      end
    }
  end

  def self.delete_credentials
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_credentials(opts)
        set_json_response(data)
      rescue => e
        set_error_on_response(e)
      end
    }
  end
end