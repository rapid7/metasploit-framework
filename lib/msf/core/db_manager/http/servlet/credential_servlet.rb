module CredentialServlet

  def self.api_path
    '/api/1/msf/credential'
  end

  def self.registered(app)
    app.get LootServlet.api_path, &get_credentials
    app.post LootServlet.api_path, &create_credential
  end

  #######
  private
  #######

  def self.get_credentials
    lambda {
      begin
        opts = parse_json_request(request, false)
        data = get_db().credentials(opts)
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.create_credential
    lambda {
      job = lambda { |opts| get_db().report_credential(opts) }
      exec_report_job(request, &job)
    }
  end
end