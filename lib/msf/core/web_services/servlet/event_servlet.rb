module EventServlet

  def self.api_path
    '/api/v1/events'
  end

  def self.registered(app)
    app.post EventServlet.api_path, &report_event
  end

  #######
  private
  #######

  def self.report_event
    lambda {
      begin
        warden.authenticate!
        job = lambda { |opts| get_db.report_event(opts) }
        exec_report_job(request, &job)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error creating the event:', code: 500)
      end
    }
  end
end