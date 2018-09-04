module PayloadServlet

  def self.api_path
    '/api/v1/payloads'
  end

  def self.registered(app)
    app.get PayloadServlet.api_path, &get_payload
    app.post PayloadServlet.api_path, &create_payload
    app.put PayloadServlet.api_path, &update_payload
    app.delete PayloadServlet.api_path, &delete_payload
  end

  #######
  private
  #######

  def self.create_payload
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.create_payload(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error creating the payload:', code: 500)
      end
    }
  end

  def self.get_payload
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.get_payload(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error getting the payload:', code: 500)
      end
    }
  end

  def self.update_payload
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.update_payload(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the payload:', code: 500)
      end
    }
  end

  def self.delete_payload
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_payload(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the payload:', code: 500)
      end
    }
  end

end
