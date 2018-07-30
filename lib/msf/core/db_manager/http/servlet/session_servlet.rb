module SessionServlet
  def self.api_path
    '/api/v1/sessions'
  end

  def self.registered(app)
    app.post SessionServlet.api_path, &report_session
    app.get SessionServlet.api_path, &get_session
  end

  #######
  private
  #######

  def self.get_session
    lambda {
      begin
        #opts = parse_json_request(request, false)
        data = get_db().get_all_sessions()
        set_json_response(data)
      rescue Exception => e
        set_error_on_response(e)
      end
    }
  end

  def self.report_session
    lambda {
      job = lambda { |opts|
        if (opts[:session_data])
          get_db().report_session_dto(opts)
        else
          get_db().report_session_host_dto(opts)
        end
      }
      exec_report_job(request, &job)
    }
  end
end