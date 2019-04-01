require 'msf/core/web_services'

module ModuleSearchServlet

  def self.api_path
    '/api/v1/modules'
  end

  def self.registered(app)
    app.get ModuleSearchServlet.api_path, &search_modules
  end

  #######
  private
  #######

  def self.search_modules
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params)
        data = Msf::WebServices.search_modules(sanitized_params)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error completing the module search:', code: 500)
      end
    }
  end


end
