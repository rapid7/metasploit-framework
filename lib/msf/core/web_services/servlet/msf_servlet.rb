module Msf::WebServices::MsfServlet

  def self.api_path
    '/api/v1/msf'
  end

  def self.api_version_path
    "#{self.api_path}/version"
  end

  def self.registered(app)
    app.get self.api_version_path, &get_msf_version
  end

  #######
  private
  #######

  def self.get_msf_version
    lambda {
      warden.authenticate!
      begin
        set_json_data_response(response: { metasploit_version: Metasploit::Framework::VERSION })
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving the version:', code: 500)
      end
    }
  end

end