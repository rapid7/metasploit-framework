module Msf::WebServices::RouteServlet

  def self.api_path
    '/api/v1/routes'
  end

  def self.api_path_remove
    "#{self.api_path}/remove"
  end

  def self.registered(app)
    app.post self.api_path, &report_session_route
    app.post self.api_path_remove, &report_session_route_remove
  end

  #######
  private
  #######

  def self.report_session_route
    lambda {
      warden.authenticate!
      begin
        job = lambda { |opts|
          print_warning(opts)
          get_db.report_session_route(opts)
        }
        exec_report_job(request, &job)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error creating the route:', code: 500)
      end
    }
  end

  def self.report_session_route_remove
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.report_session_route_remove(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting route:', code: 500)
      end
    }
  end


end
