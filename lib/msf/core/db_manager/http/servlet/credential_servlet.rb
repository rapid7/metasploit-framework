module CredentialServlet

  def self.api_path
    '/api/v1/credentials'
  end

  def self.registered(app)
    app.get CredentialServlet.api_path, &get_credentials
    app.post CredentialServlet.api_path, &create_credential
  end

  #######
  private
  #######

  def self.get_credentials
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db().creds(opts)
        includes = [:logins, :public, :private, :realm]
        # Need to append the human attribute into the private sub-object before converting to json
        # This is normally pulled from a class method from the MetasploitCredential class
        response = []
        data.each do |cred|
          json = cred.as_json(include: includes).merge('private_class' => cred.private.class.to_s)
          response << json
        end
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
        get_db().create_credential(opts)
      }
      exec_report_job(request, &job)
    }
  end
end