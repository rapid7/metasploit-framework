module AsyncCallbackServlet

  def self.api_path
    '/api/v1/async-callbacks'
  end

  def self.api_path_with_id
    "#{AsyncCallbackServlet.api_path}/?:id?"
  end

  def self.registered(app)
    app.get AsyncCallbackServlet.api_path_with_id, &get_async_callback
    app.post AsyncCallbackServlet.api_path, &create_async_callback
    app.put AsyncCallbackServlet.api_path_with_id, &update_async_callback
    app.delete AsyncCallbackServlet.api_path, &delete_async_callback
  end

  #######
  private
  #######

  def self.create_async_callback
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.create_async_callback(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error creating the async callback', code: 500)
      end
    }
  end

  def self.get_async_callback
    lambda {
      warden.authenticate!
      begin
        sanitized_params = sanitize_params(params, env['rack.request.query_hash'])
        data = get_db.async_callbacks(sanitized_params)
        data = data.first if is_single_object?(data, sanitized_params)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error getting the async callback', code: 500)
      end
    }
  end

  def self.update_async_callback
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        tmp_params = sanitize_params(params)
        opts[:id] = tmp_params[:id] if tmp_params[:id]
        data = get_db.update_async_callback(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error updating the async callback', code: 500)
      end
    }
  end

  def self.delete_async_callback
    lambda {
      warden.authenticate!
      begin
        opts = parse_json_request(request, false)
        data = get_db.delete_async_callback(opts)
        set_json_data_response(response: data)
      rescue => e
        print_error_and_create_response(error: e, message: 'There was an error deleting the async callback', code: 500)
      end
    }
  end

end
