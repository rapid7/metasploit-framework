module NoteServlet

  def self.api_path
    '/api/v1/notes'
  end

  def self.api_path_with_id
    "#{NoteServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get NoteServlet.api_path_with_id, &get_note
    app.post NoteServlet.api_path, &report_note
    app.put NoteServlet.api_path_with_id, &update_note
    app.delete NoteServlet.api_path, &delete_note
  end

  #######
  private
  #######

  def self.get_note
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.notes(sanitized_params)
        includes = [:host]
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data, includes: includes)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error retrieving notes:', code: 500)
      end
    }
  end

  def self.report_note
    lambda {
      warden.authenticate!
      job = lambda { |opts|
        get_db.report_note(opts)
      }
      exec_report_job(request, &job)
    }
  end

  def self.update_note
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_note(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the note:', code: 500)
      end
    }
  end

  def self.delete_note
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_note(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the note:', code: 500)
      end
    }
  end

end