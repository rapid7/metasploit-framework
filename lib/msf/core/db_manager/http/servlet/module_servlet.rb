module ModuleServlet

  def self.api_path
    '/api/v1/modules'
  end

  def self.registered(app)
    app.get ModuleServlet.api_path, &search_modules
  end

  #######
  private
  #######

  def self.search_modules
    lambda {
      begin
        sanitized_params = sanitize_params(params)
        data = get_db.modules(sanitized_params)
        set_json_response(data)
      rescue => e
        set_error_on_response(e)
      end
    }
  end


end
